package main

import "github.com/prometheus/client_golang/prometheus"

var (
	counterBytesDesc = prometheus.NewDesc(
		"nftables_counter_bytes",
		"Bytes, matched by counter",
		[]string{
			"name",
			"table",
			"family",
		},
		nil,
	)
	counterPacketsDesc = prometheus.NewDesc(
		"nftables_counter_packets",
		"Packets, matched by counter",
		[]string{
			"name",
			"table",
			"family",
		},
		nil,
	)
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
