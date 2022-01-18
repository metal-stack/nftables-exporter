package main

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	tableChainsDesc = prometheus.NewDesc(
		"nftables_table_chains",
		"Count chains in table",
		[]string{
			"name",
			"family",
		},
		nil,
	)
	chainRulesDesc = prometheus.NewDesc(
		"nftables_chain_rules",
		"Count rules in chain",
		[]string{
			"name",
			"family",
			"table",
			"handle",
		},
		nil,
	)
	ruleBytesDesc = prometheus.NewDesc(
		"nftables_rule_bytes",
		"Bytes, matched by rule per rule comment",
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
			"handle",
		},
		nil,
	)
	rulePacketsDesc = prometheus.NewDesc(
		"nftables_rule_packets",
		"Packets, matched by rule per rule comment",
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
			"handle",
		},
		nil,
	)
)

// nftablesManagerCollector implements the Collector interface.
type nftablesManagerCollector struct {
	opts options
}

// Describe sends the super-set of all possible descriptors of metrics
func (i nftablesManagerCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(i, ch)
}

// Collect is called by the Prometheus registry when collecting metrics.
func (i nftablesManagerCollector) Collect(ch chan<- prometheus.Metric) {
	json, err := readData(i.opts)
	if err != nil {
		log.Printf("failed parsing nftables data: %s", err)
	} else {
		nft := newNFTables(json, ch)
		nft.Collect()
	}
}

func main() {
	opts := loadOptions()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)

	prometheus.WrapRegistererWithPrefix("", reg).MustRegister(nftablesManagerCollector{opts: opts})

	log.Printf("starting on %s%s", opts.Nft.BindTo, opts.Nft.URLPath)
	http.Handle(opts.Nft.URLPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	log.Fatal(http.ListenAndServe(opts.Nft.BindTo, nil))
}
