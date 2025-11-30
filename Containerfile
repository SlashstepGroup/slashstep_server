FROM rust:1.91.1-slim

# Install dependencies
WORKDIR /usr/src/app
COPY ./ ./
RUN cargo build --release

## Expose the port.
ARG APP_PORT="3001"
ENV APP_PORT=${APP_PORT}
EXPOSE ${APP_PORT}

# Set the entrypoint
ENTRYPOINT ["/usr/src/app/target/release/slashstep_server"]