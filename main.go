package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

func readOptions() {
	configFile := flag.String("config", "/etc/nftables_exporter.yaml", "Path to nftables_exporter config file")
	flag.Parse()

	log.Printf("Read options from %s\n", *configFile)
	yamlFile, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalln(err)
	}

	err = yaml.Unmarshal(yamlFile, &options)
	log.Println(options)
	if err != nil {
		log.Fatalln(err)
	}
}

func unmarshallJSON(data []byte) []interface{} {
	var result map[string]interface{}
	jerr := json.Unmarshal(data, &result)
	if jerr != nil {
		log.Fatalln(jerr)
	}
	// fmt.Printf("Result:  %+v\n", result)
	if result["nftables"] != nil {
		return result["nftables"].([]interface{})
	}
	return nil
}

func readJSON() []interface{} {
	log.Printf("Read nft json from %s\n", options.NftablesExporter.FakeNftJSON)
	jsonFile, err := ioutil.ReadFile(options.NftablesExporter.FakeNftJSON)
	if err != nil {
		log.Fatalln(err)
	}

	return unmarshallJSON(jsonFile)
}

func readNFTables() []interface{} {
	log.Println("readNFTables")

	out, err := exec.Command("/sbin/nft", "-j", "list", "ruleset").Output()
	if err != nil {
		log.Fatal("err: ", err)
	}

	return unmarshallJSON(out)
}

func readData() []interface{} {
	if _, err := os.Stat(options.NftablesExporter.FakeNftJSON); err == nil {
		return readJSON()
	}
	return readNFTables()
}

func recordMetrics() {
	data := readData()
	if data != nil {
		for _, record := range data {
			if rec, ok := record.(map[string]interface{}); ok {
				for key, val := range rec {
					mineUnit(key, val.(map[string]interface{}))
				}
			}
			// fmt.Println(record)
		}
	}
}

func mineUnit(key string, record map[string]interface{}) {
	// fmt.Printf(" [========>] %s = %s\n", key, record)
	switch key {
	case "table":
		mineTable(record)
	case "chain":
		mineChain(record)
	case "rule":
		mineRule(record)
	}
}

func mineTable(record map[string]interface{}) {
	// fmt.Printf(" [table] %s\n", record)
	tableChains.WithLabelValues(record["name"].(string), record["family"].(string)).Set(0)
}

func mineChain(record map[string]interface{}) {
	// fmt.Printf(" [chain] %s\n", record)
	tableChains.WithLabelValues(record["table"].(string), record["family"].(string)).Add(1)
	chainRules.WithLabelValues(record["name"].(string), record["family"].(string), record["table"].(string)).Set(0)
}

func mineRule(record map[string]interface{}) {
	// fmt.Printf(" [rule] %s\n", record)
	chainName := record["chain"].(string)
	familyName := record["family"].(string)
	tableName := record["table"].(string)
	chainRules.WithLabelValues(chainName, familyName, tableName).Add(1)

	var counters map[string]interface{}
	counterType := "chain_exit"
	var interfaceInput string
	var interfaceOutput string
	var addrSource string
	var addrDestination string
	var protocol string
]	var portsSource string
	var portsDestination string

	for _, record := range record["expr"].([]interface{}) {
		for exprKey, exprVal := range record.(map[string]interface{}) {
			// log.Printf("{expr}: %+v\n", exprVal)

			switch exprKey {
			case "counter":
				{
					counters = exprVal.(map[string]interface{})
				}
			case "accept":
				{
					counterType = "rule_accept"
				}
			case "drop":
				{
					counterType = "rule_drop"
				}
			case "match":
				{
					// log.Printf("{match expr}: %+v\n", exprVal)
					for matchKey, matchVal := range exprVal.(map[string]interface{}) {
						// log.Printf("{match %s}: %+v\n", matchKey, matchVal)
						log.Printf("{matchval type}: %T\n", matchVal)
						switch matchKey {
						case "left":
							{
								for leftKey, leftVal := range matchVal.(map[string]interface{}) {
									log.Printf("{left %s}: %+v\n", leftKey, leftVal)
									switch leftKey {
									case "payload":
										{
											payloadVal := leftVal.(map[string]interface{})
											matchPayloadName = payloadVal["name"].(string)
											matchPayloadField = payloadVal["field"].(string)
											// for payloadKey, payloadVal := range leftVal.(map[string]interface{}) {

											// }
										}
									case "meta":
										{
											switch leftVal.(string) {
											case "oif", "oifname":
												{
													matchDirection = "out"
												}
											case "iif", "iifname":
												{
													matchDirection = "in"
												}
											}
										}
									}
								}
							}
						case "right":
							{
								switch matchVal.(type) {
								case string:
									{
										// log.Printf("{match right string}: %+v\n", matchVal)
										if matchDirection != "" {
											matchInterface = matchVal.(string)
										}
									}
								case map[string]interface{}:
									{

									}
								}
							}
						}
					}
				}
			}
		}
	}

	if counters != nil {
		if record["comment"] != nil {
			ruleComment := record["comment"].(string)
			ruleBytes.WithLabelValues(chainName, familyName, tableName, ruleComment, counterType).Add(counters["bytes"].(float64))
			rulePackets.WithLabelValues(chainName, familyName, tableName, ruleComment, counterType).Add(counters["packets"].(float64))
			// ruleBytes(record["chain"].(string), record["family"].(string), record["table"].(string), record["comment"].(string)).set(record["comment"])
		}
	}

}

var (
	options Options

	tableChains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nftables_table_chains",
			Help: "Count chains in table",
		},
		[]string{
			"name",
			"family",
		},
	)
	chainRules = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nftables_chain_rules",
			Help: "Count rules in chain",
		},
		[]string{
			"name",
			"family",
			"table",
		},
	)
	ruleBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nftables_rule_bytes",
			Help: "Bytes, matched by rule",
		},
		[]string{
			"chain",
			"family",
			"table",
			"comment",
			"type",
		},
	)
	rulePackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nftables_rule_packets",
			Help: "Packets, matched by rule",
		},
		[]string{
			"chain",
			"family",
			"table",
			"comment",
			"type",
		},
	)
)

func init() {
	readOptions()

	log.Printf("Starting on %s%s\n", options.NftablesExporter.BindTo, options.NftablesExporter.URLPath)

	prometheus.MustRegister(tableChains)
	prometheus.MustRegister(chainRules)
	prometheus.MustRegister(ruleBytes)
	prometheus.MustRegister(rulePackets)
}

func main() {
	evaluationIntervalSec, derr := time.ParseDuration(options.NftablesExporter.EvaluationInterval)
	log.Printf("%+v\n", evaluationIntervalSec)
	if derr != nil {
		log.Fatalln(derr)
	}

	go func() {
		for {
			recordMetrics()
			time.Sleep(time.Duration(evaluationIntervalSec.Seconds()) * time.Second)
		}
	}()

	log.Println("Listen up")
	http.Handle(options.NftablesExporter.URLPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(options.NftablesExporter.BindTo, nil))
}
