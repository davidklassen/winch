package project

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

// Match returns the hosts of a host pattern, in inventory order. Parts split
// by "," are a union. Names split by "&" in a part are an intersection, and a
// name with "!" is an exclusion.
func (inv *Inventory) Match(pattern string) ([]Host, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, errors.New("an empty host pattern")
	}
	selected := map[string]bool{}
	for part := range strings.SplitSeq(pattern, ",") {
		if strings.TrimSpace(part) == "" {
			return nil, &patternError{pattern, "an empty part"}
		}
		var in, out []map[string]bool
		for term := range strings.SplitSeq(part, "&") {
			name, neg := strings.CutPrefix(strings.TrimSpace(term), "!")
			name = strings.TrimSpace(name)
			if name == "" {
				return nil, &patternError{pattern, "an empty name"}
			}
			hosts, err := inv.named(name)
			if err != nil {
				return nil, err
			}
			if neg {
				out = append(out, hosts)
			} else {
				in = append(in, hosts)
			}
		}
		if len(in) == 0 {
			return nil, &patternError{pattern, fmt.Sprintf("the part %q needs a host or group without !, such as all & %s", strings.TrimSpace(part), strings.TrimSpace(part))}
		}
		for name := range in[0] {
			if !slices.ContainsFunc(in, func(s map[string]bool) bool { return !s[name] }) &&
				!slices.ContainsFunc(out, func(s map[string]bool) bool { return s[name] }) {
				selected[name] = true
			}
		}
	}
	var hosts []Host
	for _, h := range inv.Hosts {
		if selected[h.Name] {
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}

// patternError is an error in the syntax of a host pattern.
type patternError struct {
	pattern, msg string
}

func (e *patternError) Error() string {
	return fmt.Sprintf("host pattern %q: %s", e.pattern, e.msg)
}

// problem returns the text of an error of Match for a place that names the
// pattern already.
func problem(err error) string {
	if pe, ok := errors.AsType[*patternError](err); ok {
		return pe.msg
	}
	return err.Error()
}

// named returns the hosts of a group, or the host of that name.
func (inv *Inventory) named(name string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, h := range inv.Hosts {
		if h.Name == name || slices.Contains(h.Groups, name) {
			out[h.Name] = true
		}
	}
	names := []string{"all"}
	for _, g := range inv.Groups {
		names = append(names, g.Name)
	}
	if len(out) > 0 || slices.Contains(names, name) {
		return out, nil
	}
	for _, h := range inv.Hosts {
		names = append(names, h.Name)
	}
	return nil, fmt.Errorf("unknown host or group %q in %s%s", name, inv.File, yamlx.Suggest(name, names))
}
