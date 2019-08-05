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
	fmt.Printf(" [table] %s\n", record)
	tableChains.WithLabelValues(record["name"].(string), record["family"].(string)).Set(0)
}

func mineChain(record map[string]interface{}) {
	// fmt.Printf(" [chain] %s\n", record)
	tableChains.WithLabelValues(record["table"].(string), record["family"].(string)).Add(1)
	chainRules.WithLabelValues(record["name"].(string), record["family"].(string), record["table"].(string)).Set(0)
}

func mineRule(record map[string]interface{}) {
	fmt.Printf(" [rule] %s\n", record)
	chainRules.WithLabelValues(record["chain"].(string), record["family"].(string), record["table"].(string)).Add(1)
}

var (
	tableChains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nftables_table_chains_count",
			Help: "Count chains in table",
		},
		[]string{
			"name",
			"family",
		},
	)
	chainRules = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nftables_chain_rules_count",
			Help: "Count rules in chain",
		},
		[]string{
			"name",
			"family",
			"table",
		},
	)
)

func init() {
	prometheus.MustRegister(tableChains)
	prometheus.MustRegister(chainRules)
}

func main() {
	recordMetrics()
	fmt.Println("Socket")
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)
}
