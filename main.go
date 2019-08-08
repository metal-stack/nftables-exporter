package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v2"
)

// Options is a representation of a options
type Options struct {
	NftablesExporter struct {
		BindTo             string `yaml:"bind_to"`
		URLPath            string `yaml:"url_path"`
		EvaluationInterval string `yaml:"evaluation_interval"`
		FakeNftJSON        string `yaml:"fake_nft_json"`
	} `yaml:"nftables_exporter"`
}

// Rule - chain rule
type Rule struct {
	Chain      string
	Table      string
	Family     string
	Comment    string
	Interfaces struct {
		Input  []string
		Output []string
	}
	Addresses struct {
		Source      []string
		Destination []string
	}
	Ports struct {
		Source      []string
		Destination []string
	}
	Couters struct {
		Bytes   float64
		Packets float64
	}
}

// NewRule is Rule constructor
func NewRule(chain string, family string, table string) Rule {
	rule := Rule{}
	rule.Chain = chain
	rule.Family = family
	rule.Table = table
	rule.Comment = "empty"
	return rule
}

func arrayToTag(values []string) string {
	if len(values) == 0 {
		return "any"
	}
	return strings.Join(values, ",")
}

// Parse options from yaml config file
func readOptions() {
	configFile := flag.String("config", "/etc/nftables_exporter.yaml", "Path to nftables_exporter config file")
	flag.Parse()

	fmt.Printf("Read options from %s\n", *configFile)
	yamlFile, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalln(err)
	}

	err = yaml.Unmarshal(yamlFile, &options)
	// fmt.Println(options)
	if err != nil {
		log.Fatalln(err)
	}
}

// Parse json to gjson object
func parseJSON(data string) (gjson.Result, error) {
	if !gjson.Valid(data) {
		return gjson.Parse("{}"), errors.New("Invalid JSON")
	}
	return gjson.Get(data, "nftables"), nil
}

// Reading fake nftables json
func readFakeNFTables() (gjson.Result, error) {
	fmt.Printf("Read nft json from %s\n", options.NftablesExporter.FakeNftJSON)
	jsonFile, err := ioutil.ReadFile(options.NftablesExporter.FakeNftJSON)
	if err != nil {
		log.Fatal("Fake NFTables reading error: ", err)
	}
	return parseJSON(string(jsonFile))
}

// Get json from nftables and parse it
func readNFTables() (gjson.Result, error) {
	// fmt.Println("Reading NFTables")
	out, err := exec.Command("/sbin/nft", "-j", "list", "ruleset").Output()
	if err != nil {
		log.Fatal("NFTables reading error: ", err)
	}
	return parseJSON(string(out))
}

// Select json source and parse
func readData() (gjson.Result, error) {
	if _, err := os.Stat(options.NftablesExporter.FakeNftJSON); err == nil {
		return readFakeNFTables()
	}
	return readNFTables()
}

// Worker
func recordMetrics() {
	json, err := readData()
	if err != nil {
		fmt.Println("Error parsing json: ", err)
	}
	json.Get("#.table").ForEach(mineTable)
	json.Get("#.chain").ForEach(mineChain)
	json.Get("#.rule").ForEach(mineRule)
}

// Mining "table": {} metrics
func mineTable(key gjson.Result, value gjson.Result) bool {
	// fmt.Printf("[table] %s = %s\n", key, value)
	tableChains.WithLabelValues(value.Get("name").String(), value.Get("family").String()).Set(0)
	return true
}

// Mining "chain": {} metrics
func mineChain(key gjson.Result, value gjson.Result) bool {
	// fmt.Printf("[chain] %s = %s\n", key, value)
	table := value.Get("table").String()
	family := value.Get("family").String()
	tableChains.WithLabelValues(table, family).Inc()
	chainRules.WithLabelValues(value.Get("name").String(), family, table).Set(0)
	return true
}

// Mining "rule": {} metrics
func mineRule(key gjson.Result, value gjson.Result) bool {
	// fmt.Printf("[rule] %s = %s\n", key, value)
	rule := NewRule(value.Get("chain").String(), value.Get("family").String(), value.Get("table").String())
	chainRules.WithLabelValues(rule.Chain, rule.Family, rule.Table).Inc()
	counter := value.Get("expr.#.counter|0")
	if counter.Exists() {
		// fmt.Println(counter.Get("bytes").Float(), counter.Get("packets").Float())
		rule.Couters.Bytes = counter.Get("bytes").Float()
		rule.Couters.Packets = counter.Get("packets").Float()
		comment := value.Get("comment")
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
					switch meta.String() {
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
							rule.Addresses.Source = append(rule.Addresses.Source, mineAddress(right)...)
						case "daddr":
							rule.Addresses.Destination = append(rule.Addresses.Destination, mineAddress(right)...)
						case "sport":
							rule.Ports.Source = append(rule.Ports.Source, minePorts(right)...)
						case "dport":
							rule.Ports.Destination = append(rule.Ports.Destination, minePorts(right)...)
						}
					}
					continue
				}
			}
		}
		setRuleCounters(rule)
	}
	return true
}

func mineAddress(right gjson.Result) []string {
	switch right.Type {
	case gjson.String:
		return []string{right.String()}
	case gjson.JSON:
		{
			prefix := right.Get("prefix")
			if prefix.Exists() {
				return []string{subnetToString(prefix)}
			}
			set := right.Get("set")
			if set.Exists() {
				var addresses []string
				// fmt.Printf("[prefix] %s\n", set.Get("#.prefix"))
				for _, prefix := range set.Get("#.prefix").Array() {
					// fmt.Printf("[prefix] %s\n", prefix)
					addresses = append(addresses, subnetToString(prefix))
				}
				return addresses
			}
		}
	}
	return []string{}
}

func subnetToString(prefix gjson.Result) string {
	return fmt.Sprintf("%s/%s", prefix.Get("addr").String(), prefix.Get("len").String())
}

func minePorts(right gjson.Result) []string {
	switch right.Type {
	case gjson.String, gjson.Number:
		return []string{right.String()}
	case gjson.JSON:
		return portsToArray(right, []string{"set", "range"})
	}
	return []string{}
}

func portsToArray(right gjson.Result, keys []string) []string {
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
					ports = append(ports, portsToArray(port, []string{"set", "range"})...)
				}
			}
		}
	}
	// fmt.Printf("[ports] %s\n", ports)
	return ports
}

func setRuleCounters(rule Rule) {
	InputInterfaces := arrayToTag(rule.Interfaces.Input)
	OutputInterfaces := arrayToTag(rule.Interfaces.Output)
	SourceAddresses := arrayToTag(rule.Addresses.Source)
	DestinationAddresses := arrayToTag(rule.Addresses.Destination)
	SourcePorts := arrayToTag(rule.Ports.Source)
	DestinationPorts := arrayToTag(rule.Ports.Destination)
	ruleBytes.WithLabelValues(
		rule.Chain,
		rule.Family,
		rule.Table,
		InputInterfaces,
		OutputInterfaces,
		SourceAddresses,
		DestinationAddresses,
		SourcePorts,
		DestinationPorts,
		rule.Comment).Set(rule.Couters.Bytes)
	rulePackets.WithLabelValues(
		rule.Chain,
		rule.Family,
		rule.Table,
		InputInterfaces,
		OutputInterfaces,
		SourceAddresses,
		DestinationAddresses,
		SourcePorts,
		DestinationPorts,
		rule.Comment).Set(rule.Couters.Packets)
}

var (
	options Options

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
	readOptions()

	fmt.Printf("Starting on %s%s\n", options.NftablesExporter.BindTo, options.NftablesExporter.URLPath)

	prometheus.MustRegister(tableChains)
	prometheus.MustRegister(chainRules)
	prometheus.MustRegister(ruleBytes)
	prometheus.MustRegister(rulePackets)
}

func main() {
	evaluationIntervalSec, derr := time.ParseDuration(options.NftablesExporter.EvaluationInterval)

	if derr != nil {
		log.Fatalln(derr)
	}

	go func() {
		for {
			recordMetrics()
			time.Sleep(time.Duration(evaluationIntervalSec.Seconds()) * time.Second)
		}
	}()

	fmt.Println("Listen up")
	http.Handle(options.NftablesExporter.URLPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(options.NftablesExporter.BindTo, nil))
}
