.ONESHELL:
SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
BUILDDATE := $(shell date -Iseconds)
VERSION := $(or ${GITHUB_TAG_NAME},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))

GOFILES=$(wildcard *.go)
GONAME=$(shell basename "$(PWD)")
GOOS := linux
GOARCH := amd64
BINARY := $(GONAME)-$(GOOS)-$(GOARCH)

build:
	go build \
		-trimpath \
		-tags netgo \
		-ldflags "-X 'github.com/metal-stack/v.Version=$(VERSION)' \
				  -X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
				  -X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
				  -X 'github.com/metal-stack/v.BuildDate=$(BUILDDATE)'" \
		-o bin/$(BINARY) $(GOFILES)
	strip bin/$(BINARY)
	sha256sum bin/$(BINARY) > bin/$(BINARY).sha256

run:
	$(MAKE) build BINARY=$(GONAME)-dev
	go run $(GOFILES) --config=$(shell pwd)/nftables_exporter.yaml

clean:
	@echo "Cleaning"
	go clean

##
# Release
##

.PHONY: release
release: build
	rm -rf rel
	rm -f nftables-exporter.tgz
	mkdir -p rel/usr/bin rel/etc/systemd/system
	cp bin/nftables-exporter-$(GOOS)-$(GOARCH) rel/usr/bin/nftables-exporter
	cp systemd/nftables-exporter.service rel/etc/systemd/system
	cd rel \
	&& tar --transform="flags=r;s|-$(GOOS)-$(GOARCH)||" -cvzf nftables-exporter-$(GOOS)-$(GOARCH).tgz \
		usr/bin/nftables-exporter etc/systemd/system/nftables-exporter.service \
	&& mv nftables-exporter-$(GOOS)-$(GOARCH).tgz .. \
	&& cd -
