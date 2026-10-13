FROM gcr.io/distroless/static-debian13
COPY nftables_exporter.yaml /etc/nftables_exporter.yaml
ARG TARGETARCH
ARG TARGETVARIANT
COPY systemd/nftables-exporter.service /nftables-exporter.service
COPY --chmod=0755 bin/nftables-exporter-linux-${TARGETARCH}${TARGETVARIANT:+-${TARGETVARIANT}} /nftables-exporter
CMD ["/nftables-exporter"]
