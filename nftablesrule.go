package main

// Rule - chain rule
type Rule struct {
	Chain      string
	Table      string
	Family     string
	Comment    string
	Action     string
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

// NewRule is Rule constructor
func NewRule(chain string, family string, table string) Rule {
	rule := Rule{}
	rule.Chain = chain
	rule.Family = family
	rule.Table = table
	rule.Comment = "empty"
	rule.Action = "policy"
	return rule
}
