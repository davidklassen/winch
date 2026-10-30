package project

import (
	"embed"
	"reflect"

	"github.com/davidklassen/winch/internal/doc"
)

//go:embed topics
var topics embed.FS

// Topics returns the reference pages of the project files and of the values
// in them, in index order.
func Topics() []doc.Topic {
	keys := map[string][]doc.Key{
		"project":   doc.Keys(reflect.TypeFor[Config]()),
		"inventory": doc.Keys(reflect.TypeFor[Inventory]()),
		"pipeline":  doc.Keys(reflect.TypeFor[pipelineFile]()),
		"recipe":    doc.Keys(reflect.TypeFor[recipeFile]()),
		"step":      doc.Keys(reflect.TypeFor[stepKeys]()),
		"functions": functions,
	}
	var out []doc.Topic
	for _, name := range []string{"project", "inventory", "pipeline", "recipe", "step", "handlers", "values", "functions", "secrets", "lockout"} {
		text, _ := topics.ReadFile("topics/" + name + ".md")
		out = append(out, doc.NewTopic(name, string(text), keys[name]))
	}
	return out
}

// functions are the functions of templates and expressions. Type tells
// where a function works.
var functions = []doc.Key{
	{Name: "abs", Type: "expression", Text: "abs(n): the absolute value of the number n."},
	{Name: "all", Type: "expression", Text: "all(list, pred): true when pred is true for each element. In pred, # is the element, and .name reads the key name of a map element: all(vars.ports, # > 0)."},
	{Name: "and", Type: "template", Text: "and x y: the first empty argument, or the last argument. In an expression, and is an operator."},
	{Name: "any", Type: "expression", Text: "any(list, pred): true when pred is true for at least one element."},
	{Name: "bitand", Type: "expression", Text: "bitand(a, b): the bitwise AND of two integers."},
	{Name: "bitnand", Type: "expression", Text: "bitnand(a, b): the bitwise AND NOT of two integers."},
	{Name: "bitnot", Type: "expression", Text: "bitnot(a): the bitwise NOT of an integer."},
	{Name: "bitor", Type: "expression", Text: "bitor(a, b): the bitwise OR of two integers."},
	{Name: "bitshl", Type: "expression", Text: "bitshl(a, n): a shifted left by n bits."},
	{Name: "bitshr", Type: "expression", Text: "bitshr(a, n): a shifted right by n bits, with its sign."},
	{Name: "bitushr", Type: "expression", Text: "bitushr(a, n): a shifted right by n bits, without its sign."},
	{Name: "bitxor", Type: "expression", Text: "bitxor(a, b): the bitwise XOR of two integers."},
	{Name: "call", Type: "template", Text: "call f args: the result of the function f. Project data holds no functions."},
	{Name: "ceil", Type: "expression", Text: "ceil(n): n rounded up to an integer value."},
	{Name: "concat", Type: "expression", Text: "concat(a, b, ...): the lists joined into one list."},
	{Name: "count", Type: "expression", Text: "count(list, pred): the number of elements for which pred is true. Without pred, the number of true elements."},
	{Name: "date", Type: "expression", Text: "date(s), date(s, layout), or date(s, layout, zone): the time in the text s, such as date(\"2026-10-30\"). The layout is a Go time layout. now() is a load error, so a plan does not depend on the clock."},
	{Name: "duration", Type: "expression", Text: "duration(s): the duration in the text s, such as duration(\"1h30m\")."},
	{Name: "eq", Type: "template", Text: "eq a b: true when a equals b. With more arguments, true when a equals any of them. In an expression, use ==."},
	{Name: "filter", Type: "expression", Text: "filter(list, pred): the elements for which pred is true: filter(match(\"all\"), .name != host.name)."},
	{Name: "find", Type: "expression", Text: "find(list, pred): the first element for which pred is true, or nil."},
	{Name: "findIndex", Type: "expression", Text: "findIndex(list, pred): the index of the first element for which pred is true, or -1."},
	{Name: "findLast", Type: "expression", Text: "findLast(list, pred): the last element for which pred is true, or nil."},
	{Name: "findLastIndex", Type: "expression", Text: "findLastIndex(list, pred): the index of the last element for which pred is true, or -1."},
	{Name: "first", Type: "expression", Text: "first(list): the first element, or nil for an empty list."},
	{Name: "flatten", Type: "expression", Text: "flatten(list): the elements of the list and of its nested lists, in one list."},
	{Name: "float", Type: "expression", Text: "float(v): the number or the text v as a float."},
	{Name: "floor", Type: "expression", Text: "floor(n): n rounded down to an integer value."},
	{Name: "fromBase64", Type: "expression", Text: "fromBase64(s): the text that the base64 text s encodes."},
	{Name: "fromJSON", Type: "expression", Text: "fromJSON(s): the value of the JSON text s."},
	{Name: "fromPairs", Type: "expression", Text: "fromPairs(list): a map from a list of [key, value] pairs."},
	{Name: "ge", Type: "template", Text: "ge a b: true when a >= b."},
	{Name: "get", Type: "template, expression", Text: "get m key, or get(m, key): the value of key in the map m, or nothing when m has no such key. It reads a key that a map may leave out: {{ with get . \"endpoint\" }}Endpoint = {{ . }}{{ end }}. In an expression, get(list, i) gives the element at the index i, or nil."},
	{Name: "groupBy", Type: "expression", Text: "groupBy(list, pred): a map from each result of pred to the list of elements that give it."},
	{Name: "gt", Type: "template", Text: "gt a b: true when a > b."},
	{Name: "has", Type: "template", Text: "has list v: true when list contains v. In an expression, use v in list."},
	{Name: "hasPrefix", Type: "expression", Text: "hasPrefix(s, prefix): true when s starts with prefix. The operator startsWith does the same."},
	{Name: "hasSuffix", Type: "expression", Text: "hasSuffix(s, suffix): true when s ends with suffix. The operator endsWith does the same."},
	{Name: "html", Type: "template", Text: "html s: s with the special characters of HTML escaped."},
	{Name: "index", Type: "template", Text: "index x k: the element of the map or the list x at the key or the index k. More keys read deeper. A missing map key is an error; use get for a key that may be missing."},
	{Name: "indexOf", Type: "expression", Text: "indexOf(s, sub): the index of the first sub in s, or -1."},
	{Name: "int", Type: "expression", Text: "int(v): the number or the text v as an integer: int(\"8080\")."},
	{Name: "join", Type: "template, expression", Text: "join list sep, or join(list, sep): the elements of list joined with sep. The template join writes any element as text; the expression join takes strings only."},
	{Name: "js", Type: "template", Text: "js s: s escaped for a JavaScript string."},
	{Name: "json", Type: "template, expression", Text: "json v, or json(v): v as JSON on one line. Map keys are in sorted order, and non-ASCII characters stay UTF-8. The output is also a valid YAML value, so it writes a string into a JSON or a YAML file: \"data-root\": {{ json .vars.docker_root }}."},
	{Name: "keys", Type: "expression", Text: "keys(m): the keys of the map m, in sorted order. It cannot read vars itself: name each variable."},
	{Name: "last", Type: "expression", Text: "last(list): the last element, or nil for an empty list."},
	{Name: "lastIndexOf", Type: "expression", Text: "lastIndexOf(s, sub): the index of the last sub in s, or -1."},
	{Name: "le", Type: "template", Text: "le a b: true when a <= b."},
	{Name: "len", Type: "template, expression", Text: "len x, or len(x): the length of a string, a list, or a map."},
	{Name: "lower", Type: "expression", Text: "lower(s): s in lower case."},
	{Name: "lt", Type: "template", Text: "lt a b: true when a < b."},
	{Name: "map", Type: "expression", Text: "map(list, pred): the result of pred for each element: map(vars.users, .name)."},
	{Name: "match", Type: "expression", Text: "match(pattern): the hosts that match the host pattern, each with name, short, address, groups, and vars, as host has. It reads the inventory, not the --hosts selection. A host from match() has only the vars that need no facts. It works in steps, not in defaults. A constant pattern that matches no host is a load error."},
	{Name: "max", Type: "expression", Text: "max(a, b, ...), or max(list): the largest number."},
	{Name: "mean", Type: "expression", Text: "mean(list): the average of the numbers."},
	{Name: "median", Type: "expression", Text: "median(list): the median of the numbers."},
	{Name: "min", Type: "expression", Text: "min(a, b, ...), or min(list): the smallest number."},
	{Name: "ne", Type: "template", Text: "ne a b: true when a does not equal b."},
	{Name: "none", Type: "expression", Text: "none(list, pred): true when pred is false for each element."},
	{Name: "not", Type: "template", Text: "not x: true when x is empty or false. In an expression, not and ! are operators."},
	{Name: "one", Type: "expression", Text: "one(list, pred): true when pred is true for exactly one element."},
	{Name: "or", Type: "template", Text: "or x y: the first argument that is not empty, or the last argument. In an expression, or is an operator."},
	{Name: "print", Type: "template", Text: "print args: the arguments as text, as Go's fmt.Sprint gives them."},
	{Name: "printf", Type: "template", Text: "printf format args: the arguments formatted as Go's fmt.Sprintf does: {{ printf \"%05d\" .vars.uid }}."},
	{Name: "println", Type: "template", Text: "println args: the arguments as text, with spaces between them and a newline at the end."},
	{Name: "quote", Type: "template, expression", Text: "quote s, or quote(s): s in single quotes for sh, each ' as '\\''. A value goes into a command as it is; quote a value that must stay one word: then: !tpl \"postmap {{ quote .vars.map }}\"."},
	{Name: "reduce", Type: "expression", Text: "reduce(list, pred, initial): one value from all elements. In pred, #acc is the value so far, # the element, and #index its index: reduce(vars.sizes, #acc + #, 0)."},
	{Name: "repeat", Type: "expression", Text: "repeat(s, n): s n times."},
	{Name: "replace", Type: "expression", Text: "replace(s, old, new): s with each old replaced by new."},
	{Name: "reverse", Type: "expression", Text: "reverse(list): the elements in reverse order."},
	{Name: "round", Type: "expression", Text: "round(n): n rounded to the nearest integer value."},
	{Name: "slice", Type: "template", Text: "slice x i j: the part of the string or the list x from the index i up to j. In an expression, use x[i:j]."},
	{Name: "sort", Type: "expression", Text: "sort(list), or sort(list, \"desc\"): the elements in ascending or descending order."},
	{Name: "sortBy", Type: "expression", Text: "sortBy(list, pred), or sortBy(list, pred, \"desc\"): the elements in the order of the results of pred: sortBy(vars.users, .uid)."},
	{Name: "split", Type: "expression", Text: "split(s, sep), or split(s, sep, n): the parts of s between each sep. With n, at most n parts."},
	{Name: "splitAfter", Type: "expression", Text: "splitAfter(s, sep), or splitAfter(s, sep, n): the parts of s after each sep, each with sep at its end."},
	{Name: "sqlquote", Type: "template, expression", Text: "sqlquote s, or sqlquote(s): s as a MariaDB string literal: in single quotes, each ' as '', each \\ as \\\\. For PostgreSQL, write E before it. It assumes the default SQL mode, without NO_BACKSLASH_ESCAPES, and a UTF-8 client."},
	{Name: "string", Type: "expression", Text: "string(v): v as text: string(8080) is \"8080\"."},
	{Name: "sum", Type: "expression", Text: "sum(list), or sum(list, pred): the sum of the numbers, or of the results of pred."},
	{Name: "take", Type: "expression", Text: "take(list, n): the first n elements."},
	{Name: "timezone", Type: "expression", Text: "timezone(name): the time zone name, such as \"Europe/Berlin\", for the In method of a date."},
	{Name: "title", Type: "template", Text: "title s: s with the first letter of each word in upper case."},
	{Name: "toBase64", Type: "expression", Text: "toBase64(s): s in base64."},
	{Name: "toPairs", Type: "expression", Text: "toPairs(m): the [key, value] pairs of the map m, in sorted key order."},
	{Name: "trim", Type: "expression", Text: "trim(s), or trim(s, chars): s without white space, or without the characters in chars, at both ends."},
	{Name: "trimPrefix", Type: "expression", Text: "trimPrefix(s, prefix): s without prefix at its start."},
	{Name: "trimSuffix", Type: "expression", Text: "trimSuffix(s, suffix): s without suffix at its end."},
	{Name: "type", Type: "expression", Text: "type(v): the type of v as text: nil, bool, int, float, string, array, map, time.Time for a date, or time.Duration."},
	{Name: "uniq", Type: "expression", Text: "uniq(list): the elements without repeats, in their first order."},
	{Name: "upper", Type: "expression", Text: "upper(s): s in upper case."},
	{Name: "urlquery", Type: "template", Text: "urlquery s: s escaped for the query of a URL."},
	{Name: "values", Type: "expression", Text: "values(m): the values of the map m, in the order of its sorted keys."},
}
