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
func readFakeNFTables() (gjson.Result, error) {
	logger.Verbose("Read fake nftables data from json: %s", options.Nft.FakeNftJSON)
	jsonFile, err := os.ReadFile(options.Nft.FakeNftJSON)
	if err != nil {
		logger.Error("Fake nftables data reading error: %s", err)
	}
	return parseJSON(string(jsonFile))
}

// Get json from nftables and parse it
func readNFTables() (gjson.Result, error) {
	logger.Debug("Collecting NFTables counters...")
	nft := options.Nft.NFTLocation
	out, err := exec.Command(nft, "-j", "list", "ruleset").Output()
	if err != nil {
		log.Fatal("NFTables reading error: ", err)
	}
	return parseJSON(string(out))
}

// Select json source and parse
func readData() (gjson.Result, error) {
	if _, err := os.Stat(options.Nft.FakeNftJSON); err == nil {
		return readFakeNFTables()
	}
	return readNFTables()
}
