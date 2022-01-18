package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tidwall/gjson"
)

// nftables object
type nftables struct {
	ch   chan<- prometheus.Metric
	json gjson.Result
}

// newNFTables is NFTables constructor
func newNFTables(json gjson.Result, ch chan<- prometheus.Metric) nftables {
	log.Print("collecting metrics")
	return nftables{
		ch:   ch,
		json: json,
	}
}

// Collect metrics
func (nft nftables) Collect() {
	tableChainsDesc := prometheus.NewDesc(
		"nftables_table_chains",
		"Count chains in table",
		[]string{
			"name",
			"family",
		},
		nil,
	)
	chainRulesDesc := prometheus.NewDesc(
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
	tables := nft.json.Get("#.table").Array()
	chains := nft.json.Get("#.chain").Array()
	rules := nft.json.Get("#.rule").Array()
	for _, jTable := range tables {
		table := jTable.Get("name").String()
		family := jTable.Get("family").String()
		tableChains := 0
		for _, jChain := range chains {
			if jChain.Get("table").String() == table && jChain.Get("family").String() == family {
				tableChains++
				chain := jChain.Get("name").String()
				handle := jChain.Get("handle").String()
				chainRules := 0
				for _, jRule := range rules {
					if jRule.Get("table").String() == table && jRule.Get("family").String() == family && jRule.Get("chain").String() == chain {
						chainRules++
						nft.mineRule(jRule)
					}
				}
				nft.ch <- prometheus.MustNewConstMetric(
					chainRulesDesc,
					prometheus.GaugeValue,
					float64(chainRules),
					chain,
					family,
					table,
					handle,
				)
			}
		}
		nft.ch <- prometheus.MustNewConstMetric(
			tableChainsDesc,
			prometheus.GaugeValue,
			float64(tableChains),
			table,
			family,
		)
	}
}

// Mining "rule": {} metrics
func (nft nftables) mineRule(value gjson.Result) {
	// fmt.Printf("[rule] %s = %s\n", key, value)
	r := newNFTablesRule(value.Get("chain").String(), value.Get("family").String(), value.Get("table").String(), value.Get("handle").String())
	counter := value.Get("expr.#.counter|0")
	if counter.Exists() {
		// fmt.Println(counter.Get("bytes").Float(), counter.Get("packets").Float())
		r.Couters.Bytes = counter.Get("bytes").Float()
		r.Couters.Packets = counter.Get("packets").Float()
		comment := value.Get("comment")
		r.Action = nft.mineAction(value.Get("expr"))
		if comment.Exists() {
			r.Comment = comment.String()
		}
		for _, match := range value.Get("expr.#.match").Array() {
			// fmt.Printf("[match] %s\n", match)
			left := match.Get("left")
			right := match.Get("right")
			if left.Exists() && right.Exists() {
				// fmt.Printf("[left] %s, [right] %s\n", left, right)
				meta := left.Get("meta")
				if meta.Exists() {
					switch meta.Get("key").String() {
					case "iif", "iifname":
						r.Interfaces.Input = append(r.Interfaces.Input, right.String())
					case "oif", "oifname":
						r.Interfaces.Output = append(r.Interfaces.Output, right.String())
					}
					continue
				}
				payload := left.Get("payload")
				if payload.Exists() {
					field := payload.Get("field")
					if field.Exists() {
						switch field.String() { // TODO: ip4 \ ip6 proto as tag?
						case "saddr":
							r.Addresses.Source = append(r.Addresses.Source, nft.mineAddress(right)...)
						case "daddr":
							r.Addresses.Destination = append(r.Addresses.Destination, nft.mineAddress(right)...)
						case "sport":
							r.Ports.Source = append(r.Ports.Source, nft.minePorts(right)...)
						case "dport":
							r.Ports.Destination = append(r.Ports.Destination, nft.minePorts(right)...)
						}
					}
					continue
				}
			}
		}
		nft.setRuleCounters(r)
	}
}

func (nft nftables) mineAction(expr gjson.Result) string {
	// logger.Info("%+v", value.Get("expr.#.(drop|accept|masquerade)"))
	for _, action := range []string{"drop", "accept", "masquerade"} {
		// logger.Info("%+v", expr.Get(fmt.Sprintf("#.%s", action)))
		jAction := expr.Get(fmt.Sprintf("#.%s|0", action))
		if jAction.Exists() {
			// logger.Info("%+v, %s", jAction, action)
			return action
		}
	}
	return "policy"
}

func (nft nftables) mineAddress(right gjson.Result) []string {
	switch right.Type {
	case gjson.String:
		return []string{right.String()}
	case gjson.JSON:
		{
			prefix := right.Get("prefix")
			if prefix.Exists() {
				return []string{nft.subnetToString(prefix)}
			}
			set := right.Get("set")
			if set.Exists() {
				var addresses []string
				// fmt.Printf("[prefix] %s\n", set.Get("#.prefix"))
				for _, prefix := range set.Get("#.prefix").Array() {
					// fmt.Printf("[prefix] %s\n", prefix)
					addresses = append(addresses, nft.subnetToString(prefix))
				}
				return addresses
			}
		}
	case gjson.False, gjson.Null, gjson.Number, gjson.True:
		// noop
	}
	return []string{}
}

func (nft nftables) subnetToString(prefix gjson.Result) string {
	return fmt.Sprintf("%s/%s", prefix.Get("addr").String(), prefix.Get("len").String())
}

func (nft nftables) minePorts(right gjson.Result) []string {
	switch right.Type {
	case gjson.String, gjson.Number:
		return []string{right.String()}
	case gjson.JSON:
		return nft.portsToArray(right, []string{"set", "range"})
	case gjson.False, gjson.Null, gjson.True:
		// noop
	}
	return []string{}
}

func (nft nftables) portsToArray(right gjson.Result, keys []string) []string {
	var ports []string
	for _, key := range keys {
		values := right.Get(key)
		if values.Exists() {
			// fmt.Printf("{matchval type}: %+v\n", values)
			for _, port := range values.Array() {
				// fmt.Printf("[ptype] %s\n", port.Type)
				switch port.Type {
				case gjson.String, gjson.Number:
					ports = append(ports, port.String())
				case gjson.JSON:
					ports = append(ports, nft.portsToArray(port, []string{"set", "range"})...)
				case gjson.False, gjson.Null, gjson.True:
					// noop
				}
			}
		}
	}
	// fmt.Printf("[ports] %s\n", ports)
	return ports
}

func (nft nftables) setRuleCounters(rule nftablesRule) {
	inputInterfaces := nft.arrayToTag(rule.Interfaces.Input)
	outputInterfaces := nft.arrayToTag(rule.Interfaces.Output)
	sourceAddresses := nft.arrayToTag(rule.Addresses.Source)
	destinationAddresses := nft.arrayToTag(rule.Addresses.Destination)
	sourcePorts := nft.arrayToTag(rule.Ports.Source)
	destinationPorts := nft.arrayToTag(rule.Ports.Destination)

	ruleBytesDesc := prometheus.NewDesc(
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
	// logger.Verbose(fmt.Sprintf("%s.%s.%s => %s:%s:%s -> %s:%s:%s = %f, %s, %s", rule.Chain, rule.Family, rule.Table, InputInterfaces, SourceAddresses, SourcePorts, OutputInterfaces, DestinationAddresses, DestinationPorts, rule.Couters.Bytes, rule.Action, rule.Comment))
	nft.ch <- prometheus.MustNewConstMetric(
		ruleBytesDesc,
		prometheus.CounterValue,
		rule.Couters.Bytes,
		rule.Chain,
		rule.Family,
		rule.Table,
		inputInterfaces,
		outputInterfaces,
		sourceAddresses,
		destinationAddresses,
		sourcePorts,
		destinationPorts,
		rule.Comment,
		rule.Action,
		rule.Handle,
	)

	rulePacketsDesc := prometheus.NewDesc(
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
	nft.ch <- prometheus.MustNewConstMetric(
		rulePacketsDesc,
		prometheus.CounterValue,
		rule.Couters.Packets,
		rule.Chain,
		rule.Family,
		rule.Table,
		inputInterfaces,
		outputInterfaces,
		sourceAddresses,
		destinationAddresses,
		sourcePorts,
		destinationPorts,
		rule.Comment,
		rule.Action,
		rule.Handle,
	)
}

func (nft nftables) arrayToTag(values []string) string {
	if len(values) == 0 {
		return "any"
	}
	return strings.Join(values, ",")
}
