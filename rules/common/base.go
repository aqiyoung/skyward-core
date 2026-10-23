package common

import (
	"errors"
	"strings"

	C "github.com/metacubex/mihomo/constant"

	"golang.org/x/exp/slices"
)

var (
	errPayload = errors.New("payloadRule error")
)

// params
var (
	NoResolve = "no-resolve"
	Src       = "src"
)

type Base struct {
}

func (b *Base) ProviderNames() []string { return nil }

func ParseParams(params []string) (isSrc bool, noResolve bool) {
	isSrc = slices.Contains(params, Src)
	if isSrc {
		noResolve = true
	} else {
		noResolve = slices.Contains(params, NoResolve)
	}
	return
}

// trimArr trims every element in place. The slice already belongs to the caller
// (it comes from strings.Split on a rule line), so trimming it allocates nothing
// — the old version built a second slice per rule, and a subscription carries
// hundreds of rules.
func trimArr(arr []string) (r []string) {
	for i, e := range arr {
		arr[i] = strings.Trim(e, " ")
	}
	return arr
}

// ParseRulePayload parse rule format like:
// `tp,payload,target(,params...)` or `tp,payload(,params...)`
// needTarget control the format contains `target` in string
func ParseRulePayload(ruleRaw string, needTarget bool) (tp, payload, target string, params []string) {
	item := trimArr(strings.Split(ruleRaw, ","))
	tp = strings.ToUpper(item[0])
	if len(item) > 1 {
		switch tp {
		case "MATCH":
			// MATCH doesn't contain payload and params
			target = item[1]
		case "NOT", "OR", "AND", "SUB-RULE", "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
			// some type of rules that has comma in payload and don't need params
			if needTarget {
				l := len(item)
				target = item[l-1] // don't have params so target must at the end of slices
				item = item[:l-1]  // remove the target from slices
			}
			payload = strings.Join(item[1:], ",")
		default:
			payload = item[1]
			if len(item) > 2 {
				if needTarget {
					target = item[2]
					if len(item) > 3 {
						params = item[3:]
					}
				} else {
					params = item[2:]
				}
			}
		}
	}

	return
}

type ParseRuleFunc func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (C.Rule, error)
