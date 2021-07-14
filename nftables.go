package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tidwall/gjson"
)

// NFTables object
type NFTables struct {
	ch   chan<- prometheus.Metric
	json gjson.Result
}

// NewNFTables is NFTables constructor
func NewNFTables(json gjson.Result, ch chan<- prometheus.Metric) NFTables {
	log.Print("collecting metrics")
	nft := NFTables{}
	nft.ch = ch
	nft.json = json
	return nft
}

func (nft NFTables) arrayToTag(values []string) string {
	if len(values) == 0 {
		return "any"
	}
	return strings.Join(values, ",")
}

// Collect metrics
func (nft NFTables) Collect() {
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
func (nft NFTables) mineRule(value gjson.Result) {
	// fmt.Printf("[rule] %s = %s\n", key, value)
	rule := NewRule(value.Get("chain").String(), value.Get("family").String(), value.Get("table").String())
	counter := value.Get("expr.#.counter|0")
	if counter.Exists() {
		// fmt.Println(counter.Get("bytes").Float(), counter.Get("packets").Float())
		rule.Couters.Bytes = counter.Get("bytes").Float()
		rule.Couters.Packets = counter.Get("packets").Float()
		comment := value.Get("comment")
		rule.Action = nft.mineAction(value.Get("expr"))
		if comment.Exists() {
			rule.Comment = comment.String()
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
						rule.Interfaces.Input = append(rule.Interfaces.Input, right.String())
					case "oif", "oifname":
						rule.Interfaces.Output = append(rule.Interfaces.Output, right.String())
					}
					continue
				}
				payload := left.Get("payload")
				if payload.Exists() {
					field := payload.Get("field")
					if field.Exists() {
						switch field.String() { // TODO: ip4 \ ip6 proto as tag?
						case "saddr":
							rule.Addresses.Source = append(rule.Addresses.Source, nft.mineAddress(right)...)
						case "daddr":
							rule.Addresses.Destination = append(rule.Addresses.Destination, nft.mineAddress(right)...)
						case "sport":
							rule.Ports.Source = append(rule.Ports.Source, nft.minePorts(right)...)
						case "dport":
							rule.Ports.Destination = append(rule.Ports.Destination, nft.minePorts(right)...)
						}
					}
					continue
				}
			}
		}
		nft.setRuleCounters(rule)
	}
}

func (nft NFTables) mineAction(expr gjson.Result) string {
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

func (nft NFTables) mineAddress(right gjson.Result) []string {
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

func (nft NFTables) subnetToString(prefix gjson.Result) string {
	return fmt.Sprintf("%s/%s", prefix.Get("addr").String(), prefix.Get("len").String())
}

func (nft NFTables) minePorts(right gjson.Result) []string {
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

func (nft NFTables) portsToArray(right gjson.Result, keys []string) []string {
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

func (nft NFTables) setRuleCounters(rule Rule) {
	InputInterfaces := nft.arrayToTag(rule.Interfaces.Input)
	OutputInterfaces := nft.arrayToTag(rule.Interfaces.Output)
	SourceAddresses := nft.arrayToTag(rule.Addresses.Source)
	DestinationAddresses := nft.arrayToTag(rule.Addresses.Destination)
	SourcePorts := nft.arrayToTag(rule.Ports.Source)
	DestinationPorts := nft.arrayToTag(rule.Ports.Destination)
	// logger.Verbose(fmt.Sprintf("%s.%s.%s => %s:%s:%s -> %s:%s:%s = %f, %s, %s", rule.Chain, rule.Family, rule.Table, InputInterfaces, SourceAddresses, SourcePorts, OutputInterfaces, DestinationAddresses, DestinationPorts, rule.Couters.Bytes, rule.Action, rule.Comment))
	nft.ch <- prometheus.MustNewConstMetric(
		ruleBytesDesc,
		prometheus.CounterValue,
		rule.Couters.Bytes,
		rule.Chain,
		rule.Family,
		rule.Table,
		InputInterfaces,
		OutputInterfaces,
		SourceAddresses,
		DestinationAddresses,
		SourcePorts,
		DestinationPorts,
		rule.Comment,
		rule.Action,
	)
	nft.ch <- prometheus.MustNewConstMetric(
		rulePacketsDesc,
		prometheus.CounterValue,
		rule.Couters.Packets,
		rule.Chain,
		rule.Family,
		rule.Table,
		InputInterfaces,
		OutputInterfaces,
		SourceAddresses,
		DestinationAddresses,
		SourcePorts,
		DestinationPorts,
		rule.Comment,
		rule.Action,
	)
}
