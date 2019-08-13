package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	yaml "gopkg.in/yaml.v2"
)

var (
	exporterVersion = "0.5"
)

// NFTOptions is a inner representation of a options
type NFTOptions struct {
	BindTo      string `yaml:"bind_to"`
	URLPath     string `yaml:"url_path"`
	FakeNftJSON string `yaml:"fake_nft_json"`
	NFTLocation string `yaml:"nft_location"`
}

// Options is a representation of a options
type Options struct {
	Nft NFTOptions `yaml:"nftables_exporter"`
}

// Parse options from yaml config file
func loadOptions() Options {
	configFile := flag.String("config", "/etc/nftables_exporter.yaml", "Path to nftables_exporter config file")
	verbose := flag.Bool("verbose", false, "Verbose log output")
	debug := flag.Bool("debug", false, "Debug log output")
	version := flag.Bool("version", false, "Show application version and exit")
	flag.Parse()

	if *version {
		fmt.Printf("nftables_exporter version: %s\n", exporterVersion)
		os.Exit(0)
	}

	logger = newLogger(*verbose, *debug)

	logger.Verbose("Read options from %s\n", *configFile)
	yamlFile, err := ioutil.ReadFile(*configFile)
	if err != nil {
		logger.Panic("Failed read %s: %s", configFile, err)
	}

	opts := Options{
		NFTOptions{
			BindTo:      "9105",
			URLPath:     "/metrics",
			FakeNftJSON: "",
			NFTLocation: "/sbin/nft",
		},
	}

	if yaml.Unmarshal(yamlFile, &opts) != nil {
		logger.Panic("Failed parse %s: %s", configFile, err)
	}
	logger.Debug("Parsed options: %s", opts)
	return opts
}
