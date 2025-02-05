# nftables_exporter

Export nftables statistics to prometheus, original source from [https://github.com/Sheridan/nftables_exporter](https://github.com/Sheridan/nftables_exporter)

## Need more

- Create a feature request, describe the metric that you would like to have and attach exported from nftables json file

## Configuration

### Command line options

- `--config=/path/to/file.yaml`: Path to configuration file, default `/etc/nftables_exporter.yaml`
- `--version`: Show version and exit

### Configuration file

Example content:

```yaml
nftables_exporter:
  bind_to: "[::1]:9630"
  url_path: "/metrics"
  nft_location: /sbin/nft
  fake_nft_json: /path/to/nft.json
  log_level: warn
```

`fake_nft_json` used for debugging. I create this file with the command `nft -j list ruleset > /path/to/nft.json`. For normal exporter usage, this option is not needed.

`log_level` can be one of the following: `debug`, `info`, `warn`, `error`.
Default: `warn`.

## Example metrics

```config
# HELP nftables_chain_rules Count rules in chain
# TYPE nftables_chain_rules gauge
nftables_chain_rules{family="inet",name="forward",table="filter"} 2.0
nftables_chain_rules{family="inet",name="global",table="filter"} 15.0
# HELP nftables_table_chains Count chains in table
# TYPE nftables_table_chains gauge
nftables_table_chains{family="inet",name="filter"} 7.0
nftables_table_chains{family="ip",name="nat"} 4.0
# HELP nftables_rule_bytes Bytes, matched by rule per rule comment
# TYPE nftables_rule_bytes gauge
nftables_rule_bytes{action="accept",chain="host_spc",comment="[spc->internet] Default http [tcp]",destination_addresses="any",destination_ports="http",family="inet",input_interfaces="internal_0",output_interfaces="external_kis_0",source_addresses="10.0.0.10",source_ports="any",table="filter"} 2280.0
# HELP nftables_rule_packets Packets, matched by rule per rule comment
# TYPE nftables_rule_packets gauge
nftables_rule_packets{action="accept",chain="host_spc",comment="[spc->internet] Default http [tcp]",destination_addresses="any",destination_ports="http",family="inet",input_interfaces="internal_0",output_interfaces="external_kis_0",source_addresses="10.0.0.10",source_ports="any",table="filter"} 38.0
```

## Thank to

- [@onokonem](https://github.com/onokonem)
