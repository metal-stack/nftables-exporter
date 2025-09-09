package main

import (
	"flag"
	"log"
	"os"

	"github.com/metal-stack/v"
	"gopkg.in/yaml.v3"
)

// options is a representation of a options
type options struct {
	Nft nftOptions `yaml:"nftables_exporter"`
}

// nftOptions is a inner representation of a options
type nftOptions struct {
	BindTo      string `yaml:"bind_to"`
	URLPath     string `yaml:"url_path"`
	FakeNftJSON string `yaml:"fake_nft_json"`
	NFTLocation string `yaml:"nft_location"`
}

// Parse options from yaml config file
func loadOptions() options {
	configFile := flag.String("config", "/etc/nftables_exporter.yaml", "path to nftables_exporter config file")
	version := flag.Bool("version", false, "show application version and exit")
	flag.Parse()

	if *version {
		log.Printf("nftables_exporter version: %s", v.V)
		os.Exit(0)
	}

	log.Printf("read options from %s\n", *configFile)
	yamlFile, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("failed read %s: %s", *configFile, err)
	}

	opts := options{
		nftOptions{
			BindTo:      ":9630",
			URLPath:     "/metrics",
			FakeNftJSON: "",
			NFTLocation: "/sbin/nft",
		},
	}

	if yaml.Unmarshal(yamlFile, &opts) != nil {
		log.Fatalf("failed parse %s: %s", *configFile, err)
	}
	log.Printf("parsed options: %#v", opts)
	return opts
}
