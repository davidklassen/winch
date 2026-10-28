package module

import (
	"errors"
	"fmt"
	"strings"
)

// parseConfobj reads the configobj format that certbot writes for its
// renewal files: comments, sections such as [renewalparams] and
// [[webroot_map]], and "key = value" lines. A value is plain, quoted with
// one quote, or quoted with three quotes over one or more lines. A comma
// outside quotes makes a list. The result maps each section name to its
// keys, and each key to its items; "" is the top.
func parseConfobj(data []byte) (map[string]map[string][]string, error) {
	out := map[string]map[string][]string{"": {}}
	section := ""
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		n := i + 1
		line := strings.TrimSpace(lines[i])
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			depth := len(line) - len(strings.TrimLeft(line, "["))
			name, ok := strings.CutSuffix(line[depth:], strings.Repeat("]", depth))
			name = strings.TrimSpace(name)
			if !ok || name == "" {
				return nil, fmt.Errorf("line %d: %q is not a section header", n, line)
			}
			section = name
			out[section] = map[string][]string{}
			continue
		}
		// The raw line: a value in triple quotes keeps its white space.
		key, rest, ok := strings.Cut(lines[i], "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("line %d: no \"key = value\"", n)
		}
		rest = strings.TrimLeft(rest, " \t")
		var v []string
		var err error
		if q := rest[:min(3, len(rest))]; q == `'''` || q == `"""` {
			// The value ends at the closing quotes, on this line or a later one.
			body := rest[3:]
			for !strings.Contains(body, q) && i+1 < len(lines) {
				i++
				body += "\n" + lines[i]
			}
			end := strings.Index(body, q)
			if end < 0 {
				return nil, fmt.Errorf("line %d: %s is not closed", n, q)
			}
			for end+3 < len(body) && body[end+3] == q[0] {
				end++
			}
			if after := strings.TrimSpace(body[end+3:]); after != "" && after[0] != '#' {
				return nil, fmt.Errorf("line %d: text after the closing %s", n, q)
			}
			v = []string{body[:end]}
		} else if v, err = parseConfItems(rest); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out[section][key] = v
	}
	return out, nil
}

// parseConfItems reads a value of one line: one item, or items with commas.
func parseConfItems(s string) ([]string, error) {
	var items []string
	list := false
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" || s[0] == '#' {
			break
		}
		var item string
		if q := s[0]; q == '\'' || q == '"' {
			end := strings.IndexByte(s[1:], q)
			if end < 0 {
				return nil, fmt.Errorf("%c is not closed", q)
			}
			item, s = s[1:1+end], s[2+end:]
		} else {
			end := strings.IndexAny(s, ",#")
			if end < 0 {
				end = len(s)
			}
			item, s = strings.TrimRight(s[:end], " \t"), s[end:]
		}
		items = append(items, item)
		s = strings.TrimLeft(s, " \t")
		if s == "" || s[0] == '#' {
			break
		}
		if s[0] != ',' {
			return nil, errors.New("text after a quoted value")
		}
		list = true
		s = s[1:]
	}
	if items == nil && !list {
		items = []string{""}
	}
	return items, nil
}
