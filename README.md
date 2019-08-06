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
nftables_chain_rules{family="inet",name="input",table="filter"} 3.0
nftables_chain_rules{family="inet",name="netscan_drop",table="filter"} 4.0
nftables_chain_rules{family="inet",name="network_hosts",table="filter"} 1218.0
nftables_chain_rules{family="inet",name="output",table="filter"} 3.0
nftables_chain_rules{family="inet",name="to_self",table="filter"} 28.0
nftables_chain_rules{family="ip",name="input",table="nat"} 1.0
nftables_chain_rules{family="ip",name="output",table="nat"} 1.0
nftables_chain_rules{family="ip",name="postrouting",table="nat"} 3.0
nftables_chain_rules{family="ip",name="prerouting",table="nat"} 1.0
# HELP nftables_rule_bytes Bytes, matched by rule
# TYPE nftables_rule_bytes counter
nftables_rule_bytes{chain="forward",comment="count output accepted packets",family="inet",table="filter",type="chain_exit"} 2.388997e+06
nftables_rule_bytes{chain="global",comment="accept all connections related to connections made by us",family="inet",table="filter",type="rule_accept"} 7.664056432e+09
nftables_rule_bytes{chain="global",comment="accept from link-local",family="inet",table="filter",type="rule_accept"} 255815.0
nftables_rule_bytes{chain="global",comment="accept from spetial",family="inet",table="filter",type="rule_accept"} 0.0
nftables_rule_bytes{chain="global",comment="accept icmp",family="inet",table="filter",type="rule_accept"} 6.69844e+06
nftables_rule_bytes{chain="global",comment="accept loopback",family="inet",table="filter",type="rule_accept"} 5.215e+06
nftables_rule_bytes{chain="global",comment="accept to link-local",family="inet",table="filter",type="rule_accept"} 2508.0
nftables_rule_bytes{chain="global",comment="accept to spetial",family="inet",table="filter",type="rule_accept"} 80808.0
nftables_rule_bytes{chain="global",comment="drop burst icmp",family="inet",table="filter",type="rule_drop"} 65600.0
nftables_rule_bytes{chain="global",comment="drop connections to loopback not coming from loopback",family="inet",table="filter",type="rule_drop"} 0.0
nftables_rule_bytes{chain="global",comment="drop invalid packets",family="inet",table="filter",type="rule_drop"} 41168.0
nftables_rule_bytes{chain="input",comment="count accepted packets",family="ip",table="nat",type="chain_exit"} 1.460179e+06
nftables_rule_bytes{chain="input",comment="count input dropped packets",family="inet",table="filter",type="chain_exit"} 2.445881e+06
nftables_rule_bytes{chain="netscan_drop",comment="drop invalid packets",family="inet",table="filter",type="rule_drop"} 0.0
nftables_rule_bytes{chain="network_hosts",comment="[ap-entrance->internet] Default ftp [tcp]",family="inet",table="filter",type="rule_accept"} 0.0
nftables_rule_bytes{chain="network_hosts",comment="[ap-entrance->internet] Default ftp [udp]",family="inet",table="filter",type="rule_accept"} 0.0
nftables_rule_bytes{chain="network_hosts",comment="[ap-entrance->internet] Default http [tcp]",family="inet",table="filter",type="rule_accept"} 0.0
# HELP nftables_rule_packets Packets, matched by rule
# TYPE nftables_rule_packets counter
nftables_rule_packets{chain="forward",comment="count output accepted packets",family="inet",table="filter",type="chain_exit"} 23344.0
nftables_rule_packets{chain="global",comment="accept all connections related to connections made by us",family="inet",table="filter",type="rule_accept"} 3.226925e+06
nftables_rule_packets{chain="global",comment="accept from link-local",family="inet",table="filter",type="rule_accept"} 3088.0
nftables_rule_packets{chain="global",comment="accept from spetial",family="inet",table="filter",type="rule_accept"} 0.0
nftables_rule_packets{chain="global",comment="accept icmp",family="inet",table="filter",type="rule_accept"} 90423.0
nftables_rule_packets{chain="global",comment="accept loopback",family="inet",table="filter",type="rule_accept"} 69874.0
nftables_rule_packets{chain="global",comment="accept to link-local",family="inet",table="filter",type="rule_accept"} 14.0
nftables_rule_packets{chain="global",comment="accept to spetial",family="inet",table="filter",type="rule_accept"} 926.0
nftables_rule_packets{chain="global",comment="drop burst icmp",family="inet",table="filter",type="rule_drop"} 875.0
nftables_rule_packets{chain="global",comment="drop connections to loopback not coming from loopback",family="inet",table="filter",type="rule_drop"} 0.0
nftables_rule_packets{chain="global",comment="drop invalid packets",family="inet",table="filter",type="rule_drop"} 709.0
nftables_rule_packets{chain="input",comment="count accepted packets",family="ip",table="nat",type="chain_exit"} 19127.0
nftables_rule_packets{chain="input",comment="count input dropped packets",family="inet",table="filter",type="chain_exit"} 25747.0
nftables_rule_packets{chain="netscan_drop",comment="drop invalid packets",family="inet",table="filter",type="rule_drop"} 0.0
nftables_rule_packets{chain="network_hosts",comment="[ap-entrance->internet] Default ftp [tcp]",family="inet",table="filter",type="rule_accept"} 0.0
nftables_rule_packets{chain="network_hosts",comment="[ap-entrance->internet] Default ftp [udp]",family="inet",table="filter",type="rule_accept"} 0.0
nftables_rule_packets{chain="network_hosts",comment="[ap-entrance->internet] Default http [tcp]",family="inet",table="filter",type="rule_accept"} 0.0
```
