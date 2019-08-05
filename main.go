package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func readJSON() []interface{} {
	fmt.Println("Open")
	jsonFile, oerr := os.Open("nft.json")
	if oerr != nil {
		fmt.Println(oerr)
	}
	fmt.Println("Read")
	byteValue, rerr := ioutil.ReadAll(jsonFile)
	if rerr != nil {
		fmt.Println(rerr)
	}
	fmt.Println("Close")
	defer jsonFile.Close()

	// fmt.Println(byteValue)

	var result map[string]interface{}
	jerr := json.Unmarshal(byteValue, &result)
	if jerr != nil {
		fmt.Println(jerr)
	}
	// fmt.Printf("Result:  %+v\n", result)
	return result["nftables"].([]interface{})
}

func recordMetrics() {
	data := readJSON()
	for _, record := range data {
		if rec, ok := record.(map[string]interface{}); ok {
			for key, val := range rec {
				mineUnit(key, val.(map[string]interface{}))
			}
		}
		// fmt.Println(record)
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
	if record["comment"] != nil {
		ruleComment := record["comment"].(string)
		var counters map[string]interface{}
		counterType := "chain_exit"
		for _, record := range record["expr"].([]interface{}) {
			if rec, ok := record.(map[string]interface{}); ok {
				for key, val := range rec {
					// fmt.Printf(" [expr] %s, %+v\n", key, val)
					switch key {
					case "counter":
						counters = val.(map[string]interface{})
					case "accept":
						counterType = "rule_accept"
					case "drop":
						counterType = "rule_drop"
					}
				}
			}
		}
		if counters != nil {
			ruleBytes.WithLabelValues(chainName, familyName, tableName, ruleComment, counterType).Add(counters["bytes"].(float64))
			rulePackets.WithLabelValues(chainName, familyName, tableName, ruleComment, counterType).Add(counters["packets"].(float64))
		}
		// ruleBytes(record["chain"].(string), record["family"].(string), record["table"].(string), record["comment"].(string)).set(record["comment"])
	}
}

var (
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
	prometheus.MustRegister(tableChains)
	prometheus.MustRegister(chainRules)
	prometheus.MustRegister(ruleBytes)
	prometheus.MustRegister(rulePackets)
}

func main() {
	recordMetrics()
	fmt.Println("Socket")
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)
}
