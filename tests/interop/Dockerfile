FROM golang:1.27-bookworm AS peer
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /repo
ENTRYPOINT ["python3", "-B", "tests/interop/run.py", "peer"]

FROM rust:1-bookworm AS rust
RUN apt-get update && apt-get install -y --no-install-recommends python3 libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /repo
ENV CARGO_TARGET_DIR=/target
ENTRYPOINT ["python3", "-B", "tests/interop/run.py", "rust"]
