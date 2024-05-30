package main

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tidwall/gjson"
)

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
