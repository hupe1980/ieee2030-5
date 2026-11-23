"""Build pinned independent peers and exchange one DER control in both directions."""

import hashlib
import json
import os
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import ExitStack
from pathlib import Path

from remote_client import publish, read_when_ready

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def loopback_addresses():
    # Reserve both ephemeral ports simultaneously so a kernel cannot reuse one
    # for both listeners before the peer starts.
    with ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(2)]
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        return [f"127.0.0.1:{listener.getsockname()[1]}" for listener in sockets]


def boot_fixture(cert):
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    digest = hashlib.sha256(der).digest()
    prefix = int.from_bytes(digest[:5], "big") >> 4
    sfdi = str(prefix) + str(-sum(map(int, str(prefix))) % 10)
    # JSON is a YAML subset accepted by the peer's boot fixture loader.
    return {
        "end_devices": [
            {
                "id": "0",
                "sfdi": sfdi,
                "lfdi": digest[:20].hex().upper(),
                "enabled": True,
                "changed_time": 1,
                "function_set_assignments_list_link": {"href": "/edev/0/fsa", "all": 1},
            }
        ],
        "fsas": [
            {
                "end_device_id": "0",
                "id": "0",
                "mrid": "01",
                "der_program_list_link": {"href": "/edev/0/fsa/0/derp", "all": 1},
            }
        ],
        "der_programs": [
            {
                "end_device_id": "0",
                "fsa_id": "0",
                "id": "0",
                "mrid": "02",
                "primacy": 0,
                "der_control_list_link": {"href": "/edev/0/fsa/0/derp/0/derc", "all": 0},
            }
        ],
    }


def test(work):
    run(sys.executable, "-B", HERE / "test_pins.py")
    peers = Path(os.environ.get("SEP_INTEROP_PEERS", work / "peers")).resolve()
    run(HERE / "fetch.sh", peers)
    server_repo = peers / "ieee-2030_5-server-go"
    client_repo = (peers / "ieee-2030_5-client-go").resolve()
    server = work / "sep2server"
    client_test = work / "inverter.test"
    run("go", "build", "-mod=vendor", "-o", server, "./cmd/sep2server", cwd=server_repo)
    overlay = work / "overlay.json"
    overlay.write_text(
        json.dumps(
            {
                "Replace": {
                    str(client_repo / "internal/inverter/peer_test.go"): str(
                        HERE / "client_test.go"
                    )
                }
            }
        )
    )
    run(
        "go",
        "test",
        "-mod=readonly",
        "-overlay",
        overlay,
        "-c",
        "-o",
        client_test,
        "./internal/inverter",
        cwd=client_repo,
    )
    test_list = subprocess.check_output(
        [client_test, "-test.list=^TestRustPeerDERControl$"], text=True
    )
    if test_list.strip() != "TestRustPeerDERControl":
        raise RuntimeError("Go test binary did not register the peer probe")
    run(
        server,
        "certs",
        "generate-ca",
        "--out",
        work,
        "--years",
        "0",
        "--org",
        "Smart Energy",
        "--cn",
        "IEEE 2030.5 Root",
    )
    ca = ["--ca", work / "ca.crt", "--ca-key", work / "ca.key", "--out", work]
    run(server, "certs", "generate-server", *ca, "--hosts", "localhost,127.0.0.1")
    run(
        server,
        "certs",
        "generate-device",
        *ca,
        "--hw-serial",
        "TEST-001",
        "--hw-type",
        "1.3.6.1.4.1.40732.99",
        "--name",
        "device",
    )
    fixture = work / "boot.json"
    fixture.write_text(json.dumps(boot_fixture(work / "device.crt")))
    (work / "data").mkdir()
    key = secrets.token_hex(32)
    addr, admin = loopback_addresses()
    config = dict(
        os.environ,
        SEP2_ADDR=addr,
        SEP2_ADMIN_ADDR=admin,
        SEP2_METRICS_ADDR="127.0.0.1:0",
        SEP2_DATA_DIR=str(work / "data"),
        SEP2_ADMIN_KEY=key,
        SEP2_ADMIN_SECRET_FILE=str(work / "admin.secret"),
        SEP2_BOOT_FIXTURE=str(fixture),
        SEP2_CERT=str(work / "server.crt"),
        SEP2_KEY=str(work / "server.key"),
        SEP2_CA=str(work / "ca.crt"),
        SEP2_CA_KEY=str(work / "ca.key"),
    )
    with (work / "server.log").open("w+") as log:
        proc = subprocess.Popen(
            [server, "serve"], cwd=work, env=config, stdout=log, stderr=subprocess.STDOUT
        )
        try:
            for _ in range(200):
                if proc.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    with socket.create_connection(
                        (admin.split(":")[0], int(admin.split(":")[1])), timeout=0.2
                    ):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise TimeoutError("independent server did not become ready")
            body = {
                "derProgramHref": "/edev/0/fsa/0/derp/0",
                "type": "maxLimW",
                "maxLimW": 4321,
                "startTime": int(time.time()) + 60,
                "durationSeconds": 300,
            }
            post = urllib.request.Request(
                f"http://{admin}/api/der/controls",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
            )
            try:
                with urllib.request.urlopen(post, timeout=5) as response:
                    assert response.status == 201
                    location = response.headers["Location"]
            except urllib.error.HTTPError as error:
                raise RuntimeError(error.read().decode()) from error
            if len(sys.argv) > 1 and sys.argv[1] == "peer":
                publish(work / "ready.json", json.dumps({"address": addr, "location": location}))
                url = read_when_ready(work / "client-request", 600)
                result = subprocess.run(
                    [client_test, "-test.run=^TestRustPeerDERControl$", "-test.v"],
                    check=False,
                    env=dict(
                        os.environ,
                        SEP_INTEROP_URL=url,
                        SEP_INTEROP_CERT=str(work / "device.crt"),
                        SEP_INTEROP_KEY=str(work / "device.key"),
                        SEP_INTEROP_CA=str(work / "ca.crt"),
                    ),
                )
                publish(work / "client-result", str(result.returncode))
                # Compose stops the peer when the Rust test process exits.
                proc.wait(timeout=90)
            else:
                rust_tests(work, addr, location, client_test)
        finally:
            proc.terminate()
            proc.wait(timeout=10)


def rust_tests(work, addr, location, client_test):
    run(
        "cargo",
        "test",
        "--locked",
        "--features",
        "runtime",
        "--test",
        "interop",
        "--",
        "--ignored",
        "--nocapture",
        cwd=ROOT,
        env=dict(
            os.environ,
            SEP_INTEROP_DIR=str(work),
            SEP_INTEROP_ADDR=addr,
            SEP_INTEROP_CONTROL=location,
            SEP_INTEROP_CLIENT_TEST=str(client_test),
        ),
    )


if __name__ == "__main__":
    # Container mode shares only the test directory and the loopback namespace.
    if sys.argv[1:] == ["peer"]:
        signal.signal(signal.SIGTERM, lambda sig, frame: sys.exit(0))
        test(Path("/session"))
    elif sys.argv[1:] == ["rust"]:
        work = Path("/session")
        config = json.loads(read_when_ready(work / "ready.json", 600))
        rust_tests(work, config["address"], config["location"], HERE / "remote_client.py")
    elif not sys.argv[1:]:
        with tempfile.TemporaryDirectory(prefix="ieee20305-interop-") as directory:
            test(Path(directory))
    else:
        raise SystemExit("usage: run.py [peer|rust]")
