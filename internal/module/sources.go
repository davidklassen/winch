package module

import (
	"slices"
	"strings"
)

// source is an entry of an apt sources file that apt reads.
type source struct {
	uris, suites []string
}

// parseSources returns the enabled deb entries of an apt sources file: deb822
// stanzas when name ends in .sources, else one-line entries. It skips what
// apt cannot read.
func parseSources(name string, data []byte) []source {
	if !strings.HasSuffix(name, ".sources") {
		return parseList(string(data))
	}
	var out []source
	for _, st := range stanzas(string(data)) {
		switch strings.ToLower(st["enabled"]) {
		case "no", "false", "without", "off", "disable":
			continue
		}
		if !slices.Contains(strings.Fields(st["types"]), "deb") {
			continue
		}
		s := source{uris: strings.Fields(st["uris"]), suites: strings.Fields(st["suites"])}
		if len(s.uris) > 0 && len(s.suites) > 0 {
			out = append(out, s)
		}
	}
	return out
}

// parseList reads lines such as "deb [signed-by=/k.gpg] https://x/debian
// trixie main".
func parseList(data string) []source {
	var out []source
	for line := range strings.SplitSeq(data, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "deb" {
			continue
		}
		f = f[1:]
		if len(f) > 0 && strings.HasPrefix(f[0], "[") {
			end := slices.IndexFunc(f, func(s string) bool { return strings.HasSuffix(s, "]") })
			if end < 0 {
				continue
			}
			f = f[end+1:]
		}
		if len(f) >= 2 {
			out = append(out, source{uris: f[:1], suites: f[1:2]})
		}
	}
	return out
}

// stanzas reads deb822 text: stanzas of "Field: value" lines, separated by
// empty lines. A line that starts with white space continues the field
// before it; a line that starts with "#" is a comment. Field names are lower
// case.
func stanzas(data string) []map[string]string {
	var out []map[string]string
	var cur map[string]string
	field := ""
	for line := range strings.SplitSeq(data, "\n") {
		switch {
		case strings.HasPrefix(line, "#"):
		case strings.TrimSpace(line) == "":
			cur, field = nil, ""
		case line[0] == ' ' || line[0] == '\t':
			if cur != nil && field != "" {
				cur[field] += "\n" + strings.TrimSpace(line)
			}
		default:
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			if cur == nil {
				cur = map[string]string{}
				out = append(out, cur)
			}
			field = strings.ToLower(strings.TrimSpace(k))
			cur[field] = strings.TrimSpace(v)
		}
	}
	return out
}

// has reports whether the entry holds the URI with the suite.
func (s source) has(uri, suite string) bool {
	return slices.Contains(s.suites, suite) && slices.ContainsFunc(s.uris, func(u string) bool { return sameURI(u, uri) })
}

// sameURI reports whether a and b are the same apt URI.
func sameURI(a, b string) bool { return uriKey(a) == uriKey(b) }

// uriKey is the apt URI u without its final slashes.
func uriKey(u string) string { return strings.TrimRight(u, "/") }
