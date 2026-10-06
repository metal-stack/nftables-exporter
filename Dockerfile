FROM gcr.io/distroless/static-debian13
COPY nftables_exporter.yaml /etc/nftables_exporter.yaml
ARG TARGETARCH
COPY --chmod=0755 bin/nftables-exporter-linux-${TARGETARCH} /nftables-exporter
CMD ["/nftables-exporter"]
