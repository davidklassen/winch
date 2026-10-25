package secret

import (
	"regexp"
	"slices"
	"strings"
)

const (
	beginKey = `-----BEGIN[ A-Z0-9_-]{0,100}?PRIVATE KEY(?: BLOCK)?-----`
	endKey   = `-----END[ A-Z0-9_-]{0,100}?PRIVATE KEY(?: BLOCK)?-----`
)

var (
	keyBegin = regexp.MustCompile(beginKey)
	keyEnd   = regexp.MustCompile(endKey)
	// keyBlock is a whole block for the load warning, with its body.
	keyBlock = regexp.MustCompile(`(?s)` + beginKey + `(.*?)` + endKey)
	// sealed is the text of a !secret value in a project file.
	sealed = regexp.MustCompile(`!secret[ \t]+("[^"\n]*"|'[^'\n]*'|[^\s,\]}]+)`)
)

// pattern is a kind of token. The load warning skips a match for which skip
// returns true; the filter masks every match. When re has a group, the
// group is the secret part of the match.
type pattern struct {
	what string
	re   *regexp.Regexp
	skip func(match string) bool
}

var patterns = []pattern{
	{"an AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z2-7]{16}\b`), func(m string) bool { return strings.HasSuffix(m, "EXAMPLE") }},
	{"a GitHub token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b`), func(m string) bool {
		body := m[4:]
		return strings.Count(body, body[:1]) == len(body)
	}},
	{"a GitHub token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`), nil},
	{"a Slack token", regexp.MustCompile(`\bxox[baprs]-[0-9]+-[A-Za-z0-9-]{10,}`), nil},
	{"an age identity", regexp.MustCompile(`\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b`), nil},
	{"a Slack webhook URL", regexp.MustCompile(`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/+]{40,}`), nil},
	{"a password in a URL", regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/?#@:"<>]*:([^\s/?#"<>]+)@`), func(m string) bool {
		return strings.HasPrefix(m, "$") || strings.Contains(m, "{{")
	}},
}

// Finding is text that looks like a private key or a token, at an offset.
type Finding struct {
	Offset int
	What   string
}

// Scan returns the private keys and tokens in data that are not the text of
// a !secret value. A key needs a footer and a body of 64 characters or more.
func Scan(data []byte) []Finding {
	s := string(data)
	skip := sealed.FindAllStringIndex(s, -1)
	var out []Finding
	add := func(off int, what string) {
		if !slices.ContainsFunc(skip, func(r []int) bool { return off >= r[0] && off < r[1] }) {
			out = append(out, Finding{off, what})
		}
	}
	for _, m := range keyBlock.FindAllStringSubmatchIndex(s, -1) {
		body := strings.Join(strings.Fields(s[m[2]:m[3]]), "")
		if len(body) >= 64 {
			add(m[0], "a private key")
		}
	}
	for _, p := range patterns {
		for _, m := range p.find(s) {
			if p.skip == nil || !p.skip(s[m[0]:m[1]]) {
				add(m[0], p.what)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b Finding) int { return a.Offset - b.Offset })
	return out
}

// find returns the secret parts of the matches in s.
func (p pattern) find(s string) [][]int {
	ms := p.re.FindAllStringSubmatchIndex(s, -1)
	for i, m := range ms {
		ms[i] = m[len(m)-2:]
	}
	return ms
}
