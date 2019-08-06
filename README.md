# nftables_exporter
Export nftables statistics to prometheus

Work in progress, metric names and tags can be changed!

# Configuration
By default nftables_exporter read file /etc/nftables_exporter.yaml, but you can use parametr `--config=/path/to/file.yaml`

Example content:
```
nftables_exporter:
  bind_to: ":9105"
  url_path: "/metrics"
  evaluation_interval: 10s
```

# Examle metrics
```
# HELP nftables_chain_rules Count rules in chain
# TYPE nftables_chain_rules gauge
nftables_chain_rules{family="inet",name="forward",table="filter"} 2.0
nftables_chain_rules{family="inet",name="global",table="filter"} 15.0
# HELP nftables_table_chains Count chains in table
# TYPE nftables_table_chains gauge
nftables_table_chains{family="inet",name="filter"} 7.0
nftables_table_chains{family="ip",name="nat"} 4.0
# HELP nftables_rule_bytes Bytes, matched by rule
# TYPE nftables_rule_bytes counter
nftables_rule_bytes{chain="forward",comment="count output accepted packets",family="inet",table="filter",type="chain_exit"} 2.388997e+06
nftables_rule_bytes{chain="global",comment="accept all connections related to connections made by us",family="inet",table="filter",type="rule_accept"} 7.664056432e+09
# HELP nftables_rule_packets Packets, matched by rule
# TYPE nftables_rule_packets counter
nftables_rule_packets{chain="forward",comment="count output accepted packets",family="inet",table="filter",type="chain_exit"} 23344.0
nftables_rule_packets{chain="global",comment="accept all connections related to connections made by us",family="inet",table="filter",type="rule_accept"} 3.226925e+06
```
