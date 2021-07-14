.ONESHELL:
SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
BUILDDATE := $(shell date -Iseconds)
VERSION := $(or ${GITHUB_TAG_NAME},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))

GOFILES=$(wildcard *.go)
GONAME=$(shell basename "$(PWD)")

all:
	go build \
		-trimpath \
		-tags netgo \
		-ldflags "-X 'github.com/metal-stack/v.Version=$(VERSION)' \
				  -X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
				  -X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
				  -X 'github.com/metal-stacj/v.BuildDate=$(BUILDDATE)'" \
		-o bin/$(GONAME) $(GOFILES)
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