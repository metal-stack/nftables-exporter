package main

import (
	"log/slog"
	"net/http"
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
	ch <- upDesc
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
		slog.Error("failed to parse nftables data", "error", err)
		ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 0)
	} else {
		ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 1)
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

	slog.Info("starting http server", "bind_to", opts.Nft.BindTo, "url_path", opts.Nft.URLPath)
	http.Handle(opts.Nft.URLPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	server := http.Server{
		Addr:              opts.Nft.BindTo,
		ReadHeaderTimeout: 1 * time.Minute,
	}
	slog.Error("http server exited", "error", server.ListenAndServe().Error())
}
