package main

import (
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	options Options
	logger  Logger

	tableChains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "nftables",
			Subsystem: "table",
			Name:      "chains",
			Help:      "Count chains in table",
		},
		[]string{
			"name",
			"family",
		},
	)
	chainRules = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "nftables",
			Subsystem: "chain",
			Name:      "rules",
			Help:      "Count rules in chain",
		},
		[]string{
			"name",
			"family",
			"table",
		},
	)
	ruleBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "nftables",
			Subsystem: "rule",
			Name:      "bytes",
			Help:      "Bytes, matched by rule per rule comment",
		},
		[]string{
			"chain",
			"family",
			"table",
			"input_interfaces",
			"output_interfaces",
			"source_addresses",
			"destination_addresses",
			"source_ports",
			"destination_ports",
			"comment",
		},
	)
	rulePackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "nftables",
			Subsystem: "rule",
			Name:      "packets",
			Help:      "Packets, matched by rule per rule comment",
		},
		[]string{
			"chain",
			"family",
			"table",
			"input_interfaces",
			"output_interfaces",
			"source_addresses",
			"destination_addresses",
			"source_ports",
			"destination_ports",
			"comment",
		},
	)
)

func init() {
	options = loadOptions()
	prometheus.MustRegister(tableChains)
	prometheus.MustRegister(chainRules)
	prometheus.MustRegister(ruleBytes)
	prometheus.MustRegister(rulePackets)
}

func main() {
	evaluationIntervalSec, derr := time.ParseDuration(options.Nft.EvaluationInterval)

	if derr != nil {
		log.Fatalln(derr)
	}

	go func() {
		for {
			recordMetrics()
			time.Sleep(time.Duration(evaluationIntervalSec.Seconds()) * time.Second)
		}
	}()

	logger.Info("Starting on %s%s", options.Nft.BindTo, options.Nft.URLPath)
	http.Handle(options.Nft.URLPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(options.Nft.BindTo, nil))
}
