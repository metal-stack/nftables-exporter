package main

// nftablesRule - chain rule
type nftablesRule struct {
	Chain      string
	Table      string
	Family     string
	Comment    string
	Action     string
	Handle     string
	Interfaces struct {
		Input  []string
		Output []string
	}
	Addresses struct {
		Source      []string
		Destination []string
	}
	Ports struct {
		Source      []string
		Destination []string
	}
	Couters struct {
		Bytes   float64
		Packets float64
	}
}

// newNFTablesRule is NFTablesRule constructor
func newNFTablesRule(chain, family, table, handle string) nftablesRule {
	return nftablesRule{
		Chain:   chain,
		Family:  family,
		Table:   table,
		Comment: "empty",
		Action:  "policy",
		Handle:  handle,
	}
}
