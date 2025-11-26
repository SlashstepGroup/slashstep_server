FROM rust:1.91.1-slim

# Install dependencies
WORKDIR /usr/src/app
COPY ./ ./
RUN cargo build --release

# Set the entrypoint
ENTRYPOINT ["/usr/src/app/target/release/slashstep_server"]