package main

import (
	"log"
	"net/http"

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
