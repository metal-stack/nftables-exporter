package main

import (
	"errors"
	"log"
	"os"
	"os/exec"

	"github.com/tidwall/gjson"
)

// Parse json to gjson object
func parseJSON(data string) (gjson.Result, error) {
	if !gjson.Valid(data) {
		return gjson.Parse("{}"), errors.New("invalid JSON")
	}
	return gjson.Get(data, "nftables"), nil
}

// Reading fake nftables json
func readFakeNFTables(opts options) (gjson.Result, error) {
	log.Printf("read fake nftables data from json: %s", opts.Nft.FakeNftJSON)
	jsonFile, err := os.ReadFile(opts.Nft.FakeNftJSON)
	if err != nil {
		log.Printf("fake nftables data reading error: %s", err)
	}
	return parseJSON(string(jsonFile))
}

// Get json from nftables and parse it
func readNFTables(opts options) (gjson.Result, error) {
	log.Print("collecting nftables counters...")
	nft := opts.Nft.NFTLocation
	out, err := exec.Command(nft, "-j", "list", "ruleset").Output()
	if err != nil {
		log.Printf("nftables reading error: %s", err)
	}
	return parseJSON(string(out))
}

// Select json source and parse
func readData(opts options) (gjson.Result, error) {
	if _, err := os.Stat(opts.Nft.FakeNftJSON); err == nil {
		return readFakeNFTables(opts)
	}
	return readNFTables(opts)
}
