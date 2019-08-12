package main

import (
	"log"
	"net/http"

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
			"action",
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
			"action",
		},
	)
	promhttpHandler = promhttp.Handler()
)

// PreparePromHandler helper for call metrics collect on request
type PreparePromHandler struct {
	RecordMetrics func()
	Handler       http.Handler
}

func (p *PreparePromHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.RecordMetrics()
	p.Handler.ServeHTTP(w, r)
}

func recordMetrics() {
	json, err := readData()
	if err != nil {
		logger.Error("Failed parsing nftables data: %s", err)
	}
	json.Get("#.table").ForEach(mineTable)
	json.Get("#.chain").ForEach(mineChain)
	json.Get("#.rule").ForEach(mineRule)
}

func init() {
	options = loadOptions()
	prometheus.MustRegister(tableChains)
	prometheus.MustRegister(chainRules)
	prometheus.MustRegister(ruleBytes)
	prometheus.MustRegister(rulePackets)
}

func main() {
	logger.Info("Starting on %s%s", options.Nft.BindTo, options.Nft.URLPath)
	http.Handle(options.Nft.URLPath, &PreparePromHandler{recordMetrics, promhttp.Handler()})
	log.Fatal(http.ListenAndServe(options.Nft.BindTo, nil))
}
