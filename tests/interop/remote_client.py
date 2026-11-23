#!/usr/bin/env python3
"""Hand the listening Rust server's URL to the peer container."""

import os
import sys
import time
from pathlib import Path


def publish(path, value):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(value)
    tmp.replace(path)


def read_when_ready(path, seconds):
    deadline = time.monotonic() + seconds
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {path.name}")
        time.sleep(0.1)
    return path.read_text()


if __name__ == "__main__":
    session = Path(os.environ["SEP_INTEROP_DIR"])
    publish(session / "client-request", os.environ["SEP_INTEROP_URL"])
    sys.exit(int(read_when_ready(session / "client-result", 45)))
