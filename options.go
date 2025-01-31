package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
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
	LogLevel    string `yaml:"log_level"`
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

	logLevel := new(slog.LevelVar)
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})))
	slog.Info(fmt.Sprintf("read options from %s\n", *configFile))
	yamlFile, err := os.ReadFile(*configFile)
	if err != nil {
		slog.Error(fmt.Sprintf("failed read %s: %s", *configFile, err))
		os.Exit(1)
	}

	opts := options{
		nftOptions{
			BindTo:      "9630",
			URLPath:     "/metrics",
			FakeNftJSON: "",
			NFTLocation: "/sbin/nft",
			LogLevel:    "warn",
		},
	}

	if yaml.Unmarshal(yamlFile, &opts) != nil {
		slog.Error(fmt.Sprintf("failed parse %s: %s", *configFile, err))
		os.Exit(1)
	}
	slog.Info(fmt.Sprintf("parsed options: %#v", opts))
	switch opts.Nft.LogLevel {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "info":
		logLevel.Set(slog.LevelInfo)
	case "warn":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		slog.Error(fmt.Sprintf("invalid log level %s. Allowed: debug,info,warn,error", opts.Nft.LogLevel))
		os.Exit(1)
	}

	return opts
}
