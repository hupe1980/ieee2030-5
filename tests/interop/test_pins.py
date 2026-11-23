"""Regression test for immutable peer selection. Runs entirely offline."""

# 008-interop/SR-001
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class PeerPinTests(unittest.TestCase):
    def test_refuse_dirty_checkouts_and_floating_refs(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            peer = base / "upstream"
            subprocess.run(["git", "init", "--quiet", peer], check=True)
            (peer / "source").write_text("first revision")
            subprocess.run(["git", "-C", peer, "add", "source"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    peer,
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-qm",
                    "baseline",
                ],
                check=True,
            )
            commit = subprocess.check_output(
                ["git", "-C", peer, "rev-parse", "HEAD"], text=True
            ).strip()
            script = base / "fetch.sh"
            shutil.copy2(Path(__file__).with_name("fetch.sh"), script)
            manifest = base / "peers.lock"
            manifest.write_text(f"{peer} {commit}\n")
            dest = base / "installed"
            subprocess.run([script, dest], check=True)
            (dest / "upstream/source").write_text("changed after checkout")
            self.assertNotEqual(subprocess.run([script, dest], check=False).returncode, 0)
            manifest.write_text(f"{peer} HEAD\n")
            self.assertNotEqual(subprocess.run([script, base / "fresh"], check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
