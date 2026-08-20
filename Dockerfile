FROM rust:1.98-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang libclang-dev libdpdk-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --locked --release -p etherip

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libdpdk-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/etherip /usr/local/bin/etherip

ENTRYPOINT ["etherip"]
