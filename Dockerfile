# syntax=docker/dockerfile:1

FROM rust:1.99.1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:trixie-slim
COPY --from=build /src/target/release/netregister /usr/local/bin/netregister
ENTRYPOINT ["/usr/local/bin/netregister"]
