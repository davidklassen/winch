The functions of templates and expressions.

A template calls a function with its arguments after it, separated by
spaces: {{ join .vars.names ", " }}. An expression calls it with
parentheses: join(vars.names, ", "). The type column below tells where
a function works.

Templates also have the actions of Go's text/template: if, else, range,
with, define, template, block, break, and continue, and the variables
$x := value. In an expression, pred is a predicate: an expression that
reads the element as #, or a key of a map element as .name, such as
filter(vars.users, .uid >= 1000).
