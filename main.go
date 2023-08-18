package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// nftablesManagerCollector implements the Collector interface.
type nftablesManagerCollector struct {
	opts options
}

// Describe sends the super-set of all possible descriptors of metrics
func (i nftablesManagerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- counterBytesDesc
	ch <- counterPacketsDesc
	ch <- tableChainsDesc
	ch <- chainRulesDesc
	ch <- ruleBytesDesc
	ch <- rulePacketsDesc
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
	// set json logger as default for all log statements
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	opts := loadOptions()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)

	prometheus.WrapRegistererWithPrefix("", reg).MustRegister(nftablesManagerCollector{opts: opts})

	log.Printf("starting on %s%s", opts.Nft.BindTo, opts.Nft.URLPath)
	http.Handle(opts.Nft.URLPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	server := http.Server{
		Addr:              opts.Nft.BindTo,
		ReadHeaderTimeout: 1 * time.Minute,
	}
	log.Fatal(server.ListenAndServe())
}
