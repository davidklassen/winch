package project

import (
	"reflect"

	"github.com/davidklassen/winch/internal/doc"
	"github.com/davidklassen/winch/internal/facts"
)

// Topics returns the topics of all groups, in index order.
func Topics() []doc.Topic {
	var ts []doc.Topic
	for _, g := range Groups() {
		ts = append(ts, g.Topics...)
	}
	return ts
}

// Groups returns the topics of winch doc in their groups, in index order.
func Groups() []doc.Group {
	factKeys := doc.Keys(reflect.TypeFor[facts.Facts]())
	for i := range factKeys {
		factKeys[i].Default = ""
	}
	keys := map[string][]doc.Key{
		"project":   doc.Keys(reflect.TypeFor[Config]()),
		"inventory": doc.Keys(reflect.TypeFor[Inventory]()),
		"pipeline":  doc.Keys(reflect.TypeFor[pipelineFile]()),
		"recipe":    doc.Keys(reflect.TypeFor[recipeFile]()),
		"step":      doc.Keys(reflect.TypeFor[stepKeys]()),
		"facts":     factKeys,
	}
	functions := map[string][]doc.Key{
		"templates":   templateFunctions,
		"expressions": expressionFunctions,
	}
	groups := []doc.Group{
		{Title: "Project files", Topics: []doc.Topic{projectTopic, inventoryTopic, pipelineTopic, recipeTopic, stepTopic, handlersTopic}},
		{Title: "Values", Topics: []doc.Topic{variablesTopic, templatesTopic, expressionsTopic, factsTopic, secretsTopic}},
		{Title: "Running", Topics: []doc.Topic{workflowTopic, remoteTopic}},
	}
	for _, g := range groups {
		for i := range g.Topics {
			t := &g.Topics[i]
			t.Keys = keys[t.Name]
			for _, f := range functions[t.Name] {
				f.Type = "function"
				t.Functions = append(t.Functions, f)
			}
		}
	}
	return groups
}

// templateFunctions are the functions of templates.
var templateFunctions = []doc.Key{
	{Name: "and", Text: "and x y: the first empty argument, or the last argument. In an expression, and is an operator."},
	{Name: "call", Text: "call f args: the result of the function f. Project data holds no functions."},
	{Name: "eq", Text: "eq a b: true when a equals b. With more arguments, true when a equals any of them. In an expression, use ==."},
	{Name: "ge", Text: "ge a b: true when a >= b."},
	{Name: "get", Text: "get m key: the value of key in the map m, or nothing when m has no such key. It reads a key that a map may leave out: {{ with get . \"endpoint\" }}Endpoint = {{ . }}{{ end }}."},
	{Name: "gt", Text: "gt a b: true when a > b."},
	{Name: "has", Text: "has list v: true when list contains v. In an expression, use v in list."},
	{Name: "html", Text: "html s: s with the special characters of HTML escaped."},
	{Name: "index", Text: "index x k: the element of the map or the list x at the key or the index k. More keys read deeper. A missing map key is an error. Use get for a key that may be missing."},
	{Name: "join", Text: "join list sep: the elements of list as text, joined with sep."},
	{Name: "js", Text: "js s: s escaped for a JavaScript string."},
	{Name: "json", Text: "json v: v as JSON on one line. Map keys are in sorted order, and non-ASCII characters stay UTF-8. The output is also a valid YAML value, so it writes a string into a JSON or a YAML file: \"data-root\": {{ json .vars.docker_root }}."},
	{Name: "le", Text: "le a b: true when a <= b."},
	{Name: "len", Text: "len x: the length of a string, a list, or a map."},
	{Name: "lt", Text: "lt a b: true when a < b."},
	{Name: "ne", Text: "ne a b: true when a does not equal b."},
	{Name: "not", Text: "not x: true when x is empty or false. In an expression, not and ! are operators."},
	{Name: "or", Text: "or x y: the first argument that is not empty, or the last argument. In an expression, or is an operator."},
	{Name: "print", Text: "print args: the arguments as text, as Go's fmt.Sprint gives them."},
	{Name: "printf", Text: "printf format args: the arguments formatted as Go's fmt.Sprintf does: {{ printf \"%05d\" .vars.uid }}."},
	{Name: "println", Text: "println args: the arguments as text, with spaces between them and a newline at the end."},
	{Name: "quote", Text: "quote s: s in single quotes for sh, each ' as '\\''. A value goes into a command as it is. Quote a value that must stay one word: then: !tpl \"postmap {{ quote .vars.map }}\"."},
	{Name: "slice", Text: "slice x i j: the part of the string or the list x from the index i up to j. In an expression, use x[i:j]."},
	{Name: "sqlquote", Text: "sqlquote s: s as a MariaDB string literal: in single quotes, each ' as '', each \\ as \\\\. For PostgreSQL, write E before it. It assumes the default SQL mode, without NO_BACKSLASH_ESCAPES, and a UTF-8 client."},
	{Name: "title", Text: "title s: s with the first letter of each word in upper case."},
	{Name: "urlquery", Text: "urlquery s: s escaped for the query of a URL."},
}

// expressionFunctions are the functions of expressions.
var expressionFunctions = []doc.Key{
	{Name: "abs", Text: "abs(n): the absolute value of the number n."},
	{Name: "all", Text: "all(list, pred): true when pred is true for each element. In pred, # is the element, and .name reads the key name of a map element: all(vars.ports, # > 0)."},
	{Name: "any", Text: "any(list, pred): true when pred is true for at least one element."},
	{Name: "bitand", Text: "bitand(a, b): the bitwise AND of two integers."},
	{Name: "bitnand", Text: "bitnand(a, b): the bitwise AND NOT of two integers."},
	{Name: "bitnot", Text: "bitnot(a): the bitwise NOT of an integer."},
	{Name: "bitor", Text: "bitor(a, b): the bitwise OR of two integers."},
	{Name: "bitshl", Text: "bitshl(a, n): a shifted left by n bits."},
	{Name: "bitshr", Text: "bitshr(a, n): a shifted right by n bits, with its sign."},
	{Name: "bitushr", Text: "bitushr(a, n): a shifted right by n bits, without its sign."},
	{Name: "bitxor", Text: "bitxor(a, b): the bitwise XOR of two integers."},
	{Name: "ceil", Text: "ceil(n): n rounded up to an integer value."},
	{Name: "concat", Text: "concat(a, b, ...): the lists joined into one list."},
	{Name: "count", Text: "count(list, pred): the number of elements for which pred is true. Without pred, the number of true elements."},
	{Name: "date", Text: "date(s), date(s, layout), or date(s, layout, zone): the time in the text s, such as date(\"2026-10-30\"). The layout is a Go time layout. now() is a load error, so a plan does not depend on the clock."},
	{Name: "duration", Text: "duration(s): the duration in the text s, such as duration(\"1h30m\")."},
	{Name: "filter", Text: "filter(list, pred): the elements for which pred is true: filter(match(\"all\"), .name != host.name)."},
	{Name: "find", Text: "find(list, pred): the first element for which pred is true, or nil."},
	{Name: "findIndex", Text: "findIndex(list, pred): the index of the first element for which pred is true, or -1."},
	{Name: "findLast", Text: "findLast(list, pred): the last element for which pred is true, or nil."},
	{Name: "findLastIndex", Text: "findLastIndex(list, pred): the index of the last element for which pred is true, or -1."},
	{Name: "first", Text: "first(list): the first element, or nil for an empty list."},
	{Name: "flatten", Text: "flatten(list): the elements of the list and of its nested lists, in one list."},
	{Name: "float", Text: "float(v): the number or the text v as a float."},
	{Name: "floor", Text: "floor(n): n rounded down to an integer value."},
	{Name: "fromBase64", Text: "fromBase64(s): the text that the base64 text s encodes."},
	{Name: "fromJSON", Text: "fromJSON(s): the value of the JSON text s."},
	{Name: "fromPairs", Text: "fromPairs(list): a map from a list of [key, value] pairs."},
	{Name: "get", Text: "get(m, key): the value of key in the map m, or nil when m has no such key. get(list, i) gives the element at the index i, or nil."},
	{Name: "groupBy", Text: "groupBy(list, pred): a map from each result of pred to the list of elements that give it."},
	{Name: "hasPrefix", Text: "hasPrefix(s, prefix): true when s starts with prefix. The operator startsWith does the same."},
	{Name: "hasSuffix", Text: "hasSuffix(s, suffix): true when s ends with suffix. The operator endsWith does the same."},
	{Name: "indexOf", Text: "indexOf(s, sub): the index of the first sub in s, or -1."},
	{Name: "int", Text: "int(v): the number or the text v as an integer: int(\"8080\")."},
	{Name: "join", Text: "join(list, sep): the strings of list joined with sep."},
	{Name: "json", Text: "json(v): v as JSON on one line. Map keys are in sorted order, and non-ASCII characters stay UTF-8. The output is also a valid YAML value."},
	{Name: "keys", Text: "keys(m): the keys of the map m, in sorted order. It cannot read vars itself: name each variable."},
	{Name: "last", Text: "last(list): the last element, or nil for an empty list."},
	{Name: "lastIndexOf", Text: "lastIndexOf(s, sub): the index of the last sub in s, or -1."},
	{Name: "len", Text: "len(x): the length of a string, a list, or a map."},
	{Name: "lower", Text: "lower(s): s in lower case."},
	{Name: "map", Text: "map(list, pred): the result of pred for each element: map(vars.users, .name)."},
	{Name: "match", Text: "match(pattern): the hosts that match the host pattern, each with name, short, address, groups, and vars, as host has. It reads the inventory, not the --hosts selection. A host from match() has only the vars that need no facts. It works in steps, not in defaults. A constant pattern that matches no host is a load error."},
	{Name: "max", Text: "max(a, b, ...), or max(list): the largest number."},
	{Name: "mean", Text: "mean(list): the average of the numbers."},
	{Name: "median", Text: "median(list): the median of the numbers."},
	{Name: "min", Text: "min(a, b, ...), or min(list): the smallest number."},
	{Name: "none", Text: "none(list, pred): true when pred is false for each element."},
	{Name: "one", Text: "one(list, pred): true when pred is true for exactly one element."},
	{Name: "quote", Text: "quote(s): s in single quotes for sh, each ' as '\\''. A value goes into a command as it is. Quote a value that must stay one word: then: !expr '\"postmap \" + quote(vars.map)'."},
	{Name: "reduce", Text: "reduce(list, pred, initial): one value from all elements. In pred, #acc is the value so far, # the element, and #index its index: reduce(vars.sizes, #acc + #, 0)."},
	{Name: "repeat", Text: "repeat(s, n): s n times."},
	{Name: "replace", Text: "replace(s, old, new): s with each old replaced by new."},
	{Name: "reverse", Text: "reverse(list): the elements in reverse order."},
	{Name: "round", Text: "round(n): n rounded to the nearest integer value."},
	{Name: "sort", Text: "sort(list), or sort(list, \"desc\"): the elements in ascending or descending order."},
	{Name: "sortBy", Text: "sortBy(list, pred), or sortBy(list, pred, \"desc\"): the elements in the order of the results of pred: sortBy(vars.users, .uid)."},
	{Name: "split", Text: "split(s, sep), or split(s, sep, n): the parts of s between each sep. With n, at most n parts."},
	{Name: "splitAfter", Text: "splitAfter(s, sep), or splitAfter(s, sep, n): the parts of s after each sep, each with sep at its end."},
	{Name: "sqlquote", Text: "sqlquote(s): s as a MariaDB string literal: in single quotes, each ' as '', each \\ as \\\\. For PostgreSQL, write E before it. It assumes the default SQL mode, without NO_BACKSLASH_ESCAPES, and a UTF-8 client."},
	{Name: "string", Text: "string(v): v as text: string(8080) is \"8080\"."},
	{Name: "sum", Text: "sum(list), or sum(list, pred): the sum of the numbers, or of the results of pred."},
	{Name: "take", Text: "take(list, n): the first n elements."},
	{Name: "timezone", Text: "timezone(name): the time zone name, such as \"Europe/Berlin\", for the In method of a date."},
	{Name: "toBase64", Text: "toBase64(s): s in base64."},
	{Name: "toPairs", Text: "toPairs(m): the [key, value] pairs of the map m, in sorted key order."},
	{Name: "trim", Text: "trim(s), or trim(s, chars): s without white space, or without the characters in chars, at both ends."},
	{Name: "trimPrefix", Text: "trimPrefix(s, prefix): s without prefix at its start."},
	{Name: "trimSuffix", Text: "trimSuffix(s, suffix): s without suffix at its end."},
	{Name: "type", Text: "type(v): the type of v as text: nil, bool, int, float, string, array, map, time.Time for a date, or time.Duration."},
	{Name: "uniq", Text: "uniq(list): the elements without repeats, in their first order."},
	{Name: "upper", Text: "upper(s): s in upper case."},
	{Name: "values", Text: "values(m): the values of the map m, in the order of its sorted keys."},
}
