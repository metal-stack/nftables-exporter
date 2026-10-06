package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tidwall/gjson"
)

func TestSetElements(t *testing.T) {
	const ruleset = `{"nftables": [
		{"metainfo": {"version": "1.0"}},
		{"table": {"family": "inet", "name": "filter"}},
		{"set": {"family": "inet", "table": "filter", "name": "blocked", "type": "ipv4_addr", "size": 100, "count": 2}},
		{"set": {"family": "inet", "table": "filter", "name": "empty", "type": "ipv4_addr", "count": 0}},
		{"set": {"family": "inet", "table": "other", "name": "blocked", "type": "ipv4_addr", "count": 1}},
		{"set": {"family": "inet", "table": "filter", "name": "blocked_v6", "type": "ipv6_addr", "count": 2}},
		{"set": {"family": "ip", "table": "filter", "name": "blocked", "type": "ipv4_addr", "count": 1}},
		{"set": {"family": "ip6", "table": "filter", "name": "blocked", "type": "ipv6_addr", "count": 4}},
		{"set": {"family": "ip6", "table": "filter", "name": "empty_v6", "type": "ipv6_addr", "count": 0}}
	]}`
	path := filepath.Join(t.TempDir(), "ruleset.json")
	if err := os.WriteFile(path, []byte(ruleset), 0600); err != nil {
		t.Fatal(err)
	}

	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(nftablesManagerCollector{opts: options{Nft: nftOptions{FakeNftJSON: path}}}); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	type setKey struct{ name, family, table string }
	got := make(map[setKey]float64)
	for _, family := range families {
		if family.GetName() != "nftables_set_elements" {
			continue
		}
		for _, metric := range family.GetMetric() {
			key := setKey{}
			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "name":
					key.name = label.GetValue()
				case "family":
					key.family = label.GetValue()
				case "table":
					key.table = label.GetValue()
				}
			}
			got[key] = metric.GetGauge().GetValue()
		}
	}
	want := map[setKey]float64{
		{name: "blocked", family: "inet", table: "filter"}:    2,
		{name: "empty", family: "inet", table: "filter"}:      0,
		{name: "blocked", family: "inet", table: "other"}:     1,
		{name: "blocked_v6", family: "inet", table: "filter"}: 2,
		{name: "blocked", family: "ip", table: "filter"}:      1,
		{name: "blocked", family: "ip6", table: "filter"}:     4,
		{name: "empty_v6", family: "ip6", table: "filter"}:    0,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("nftables_set_elements mismatch (-want +got):\n%s", diff)
	}
}

func TestMineAddress(t *testing.T) {
	nft := nftables{}

	cases := []struct {
		json string
		want []string
	}{
		{ // plain string
			json: `"8.8.8.8"`,
			want: []string{"8.8.8.8"},
		},

		{ // anonymous ip addr only set
			json: `{"set": ["8.8.8.8","10.96.0.10","21.21.0.242"]}}`,
			want: []string{"10.96.0.10", "21.21.0.242", "8.8.8.8"},
		},

		{ // anonymous set with subnets only
			json: `{"set": [{"prefix": {"addr": "10.10.0.0","len": 16}}, {"prefix": {"addr": "10.20.0.0","len": 16}}]}`,
			want: []string{"10.10.0.0/16", "10.20.0.0/16"},
		},

		{ // anonymous mixed (ip addr and subnets) set
			json: `{"set": ["8.8.8.8","10.96.0.10","21.21.0.242",{"prefix": {"addr": "127.0.0.0","len": 8}}]}`,
			want: []string{"10.96.0.10", "127.0.0.0/8", "21.21.0.242", "8.8.8.8"},
		},

		{ // single subnet
			json: `{"prefix": {"addr": "127.0.0.0","len": 8}}`,
			want: []string{"127.0.0.0/8"},
		},
	}
	for i, c := range cases {
		json := gjson.Parse(c.json)
		got := nft.mineAddress(json)

		sort.Strings(got)
		if !cmp.Equal(got, c.want) {
			t.Errorf("mineAddress case#%d failed:\n%v\n", i, cmp.Diff(c.want, got))
		}
	}
}
