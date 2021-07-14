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
