FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates iproute2 && rm -rf /var/lib/apt/lists/*
COPY target/release/scale_mesh /usr/local/bin/scale_mesh
ENTRYPOINT ["/usr/local/bin/scale_mesh"]
CMD ["5000"]
