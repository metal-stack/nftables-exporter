.ONESHELL:
SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
BUILDDATE := $(shell date -Iseconds)
VERSION := $(or ${GITHUB_TAG_NAME},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))

GOFILES=$(wildcard *.go)
GONAME=$(shell basename "$(PWD)")
GO_BUILDINFO= -X 'github.com/metal-stack/v.Version=$(VERSION)' \
				  -X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
				  -X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
				  -X 'github.com/metal-stack/v.BuildDate=$(BUILDDATE)'

run:
	$(MAKE) app-local
	go run $(GOFILES) --config=$(shell pwd)/nftables_exporter.yaml

clean:
	@echo "Cleaning"
	go clean

##
# Build
##
app-local:
	go build \
		-trimpath \
		-tags netgo \
		-ldflags "$(GO_BUILDINFO)" \
		-o bin/$(GONAME)-dev $(GOFILES)
	strip bin/$(GONAME)-dev
app-local-goos-goarch:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-trimpath \
		-tags netgo \
		-ldflags "$(GO_BUILDINFO)" \
		-o bin/$(GONAME)-$(GOOS)-$(GOARCH) $(GOFILES)
	strip bin/$(GONAME)-$(GOOS)-$(GOARCH)
	sha256sum bin/$(GONAME)-$(GOOS)-$(GOARCH) > bin/$(GONAME)-$(GOOS)-$(GOARCH).sha256

build: \
		build-linux-amd64 \
		build-linux-arm64

build-linux-amd64:
	GOOS=linux GOARCH=amd64 $(MAKE) app-local-goos-goarch
build-linux-arm64:
	GOOS=linux GOARCH=arm64 $(MAKE) app-local-goos-goarch

##
# Release
##

.PHONY: release-goos-goarch release
release: \
		release-linux-amd64 \
		release-linux-arm64

release-linux-amd64:
	GOOS=linux GOARCH=amd64 $(MAKE) release-goos-goarch
release-linux-arm64:
	GOOS=linux GOARCH=arm64 $(MAKE) release-goos-goarch

release-goos-goarch: build-$(GOOS)-$(GOARCH)
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
