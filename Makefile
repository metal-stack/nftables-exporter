GOFILES=$(wildcard *.go)
GONAME=$(shell basename "$(PWD)")

all:
	go build -v -o bin/$(GONAME) $(GOFILES)
	strip bin/$(GONAME)

run: all
	go run $(GOFILES) --config=$(shell pwd)/nftables_exporter.yaml --debug --verbose

clean:
	@echo "Cleaning"
	go clean

.PHONY: release
release: all
	rm -rf rel
	mkdir -p rel/usr/bin rel/etc/systemd/system
	cp bin/nftables-exporter rel/usr/bin
	cp systemd/nftables-exporter.service rel/etc/systemd/system
	cd rel \
	&& tar -cvzf nftables-exporter.tgz usr/bin/nftables-exporter etc/systemd/system/nftables-exporter.service \
	&& mv nftables-exporter.tgz .. \
	&& cd -