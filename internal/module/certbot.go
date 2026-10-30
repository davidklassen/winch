package module

import (
	"bytes"
	"cmp"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Certbot struct {
	Name          string        `yaml:"name,required" json:"name" line:"certificate name in /etc/letsencrypt" doc:"Certificate name in /etc/letsencrypt."`
	Domains       yamlx.Strings `yaml:"domains,required" json:"domains" line:"no wildcards" doc:"No wildcards. A wildcard needs a DNS challenge."`
	Email         string        `yaml:"email,required" json:"email" line:"Let's Encrypt account address" doc:"Let's Encrypt account address."`
	Authenticator string        `yaml:"authenticator" json:"authenticator,omitempty" line:"challenge plugin" doc:"Challenge plugin: nginx, apache, standalone, or webroot. The nginx and apache plugins do not change the config of the web server. standalone binds port 80 itself; pre_hook and post_hook can stop and start what holds that port. webroot needs webroot_path." default:"nginx"`
	WebrootPath   string        `yaml:"webroot_path" json:"webroot_path,omitempty" line:"web root for webroot" doc:"Web root for webroot."`
	PreHook       *string       `yaml:"pre_hook" json:"pre_hook,omitempty" line:"command before each try" doc:"Command before each try to get a certificate. certbot stores it in a file that other users can read, so it cannot hold a secret. A hook that needs a secret reads it from a root-only file that a file step writes."`
	PostHook      *string       `yaml:"post_hook" json:"post_hook,omitempty" line:"command after each try" doc:"Command after each try to get a certificate. certbot stores it in a file that other users can read, so it cannot hold a secret."`
	DeployHook    *string       `yaml:"deploy_hook" json:"deploy_hook,omitempty" line:"command after each new certificate" doc:"Command after each new certificate, also the first. A failed hook fails the step, and the next apply runs it again. It cannot hold a secret."`
	ReuseKey      bool          `yaml:"reuse_key" json:"reuse_key,omitempty" line:"keep the private key at renewal" doc:"Keep the private key at renewal."`

	// PendingHooks are the failed hooks recorded by the helper.
	PendingHooks []string `yaml:"-" json:"-"`
	issue        bool
}

func (c *Certbot) Main() string { return c.Name }

var (
	certNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	domainRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

func (c *Certbot) Validate() error {
	if !certNameRe.MatchString(c.Name) {
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf(`%q is not a certificate name: letters, digits, ".", "_", and "-", starting with a letter or digit`, c.Name)}
	}
	if len(c.Domains) == 0 {
		return &yamlx.FieldError{Field: "domains", Msg: "needs at least one domain"}
	}
	for i, d := range c.Domains {
		switch {
		case strings.HasPrefix(d, "*."):
			return &yamlx.FieldError{Field: "domains", Msg: fmt.Sprintf("%q is a wildcard, which needs a DNS challenge; the nginx, apache, standalone, and webroot authenticators answer only HTTP challenges", d)}
		case !domainRe.MatchString(d):
			return &yamlx.FieldError{Field: "domains", Msg: fmt.Sprintf("%q is not a domain name such as example.com; certbot takes lowercase names", d)}
		case len(d) > 253:
			return &yamlx.FieldError{Field: "domains", Msg: fmt.Sprintf("%q is longer than 253 characters", d)}
		case slices.Contains(c.Domains[:i], d):
			return &yamlx.FieldError{Field: "domains", Msg: fmt.Sprintf("%q is in the list twice", d)}
		}
	}
	if user, host, ok := strings.Cut(c.Email, "@"); !ok || user == "" || host == "" || strings.ContainsFunc(c.Email, unicode.IsSpace) {
		return &yamlx.FieldError{Field: "email", Msg: fmt.Sprintf("%q is not an email address", c.Email)}
	}
	switch c.Authenticator {
	case "", "nginx", "apache", "standalone":
	case "webroot":
		if c.WebrootPath == "" {
			return &yamlx.FieldError{Field: "authenticator", Msg: "webroot needs webroot_path"}
		}
	default:
		return &yamlx.FieldError{Field: "authenticator", Msg: fmt.Sprintf("%q is not an authenticator; use nginx, apache, standalone, or webroot", c.Authenticator)}
	}
	if c.WebrootPath != "" {
		if c.Authenticator != "webroot" {
			return &yamlx.FieldError{Field: "webroot_path", Msg: "webroot_path needs authenticator: webroot"}
		}
		if err := checkAbs("webroot_path", c.WebrootPath); err != nil {
			return err
		}
		if strings.Contains(c.WebrootPath, ",") {
			return &yamlx.FieldError{Field: "webroot_path", Msg: `has a ",", which certbot reads as a list`}
		}
	}
	for _, h := range []struct {
		field string
		hook  *string
	}{{"pre_hook", c.PreHook}, {"post_hook", c.PostHook}, {"deploy_hook", c.DeployHook}} {
		if err := checkCommand(h.field, h.hook); err != nil {
			return err
		}
	}
	return nil
}

const letsencrypt = "/etc/letsencrypt"

func renewalPath(dir, name string) string { return path.Join(dir, "renewal", name+".conf") }

func (c *Certbot) authenticator() string { return cmp.Or(c.Authenticator, "nginx") }

// setting is a setting of a certificate, as the renewal file holds it.
type setting struct{ key, value string }

// settings returns the settings of the step that the check compares, in plan
// order. An unset hook has the value "".
func (c *Certbot) settings() []setting {
	hook := func(h *string) string {
		if h == nil {
			return ""
		}
		return *h
	}
	return []setting{
		{"authenticator", c.authenticator()},
		{"installer", ""},
		{"webroot_path", c.WebrootPath},
		{"pre_hook", hook(c.PreHook)},
		{"post_hook", hook(c.PostHook)},
		{"deploy_hook", hook(c.DeployHook)},
		{"reuse_key", fmt.Sprint(c.ReuseKey)},
	}
}

// certState is a certificate on the host: the DNS names and the expiry of its
// certificate, nil and zero when the file is missing, and the settings of its
// renewal file.
type certState struct {
	domains  []string
	notAfter time.Time
	settings map[string]string
}

// readCertState reads the certificate name in the certbot directory dir. It
// returns nil when the certificate has no renewal file.
func readCertState(dir, name string) (*certState, error) {
	conf := renewalPath(dir, name)
	data, err := os.ReadFile(conf)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sections, err := parseConfobj(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", conf, err)
	}
	params := sections["renewalparams"]
	first := func(key string) string {
		if v := params[key]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	cur := &certState{settings: map[string]string{
		"reuse_key": fmt.Sprint(first("reuse_key") == "True"),
	}}
	for key, from := range map[string]string{"authenticator": "authenticator", "pre_hook": "pre_hook", "post_hook": "post_hook", "deploy_hook": "renew_hook"} {
		if v := first(from); v != "" {
			cur.settings[key] = v
		}
	}
	if v := first("installer"); v != "" && v != "None" {
		cur.settings["installer"] = v
	}
	if v := params["webroot_path"]; len(v) > 0 {
		cur.settings["webroot_path"] = strings.Join(v, ",")
	}
	certPath := path.Join(dir, "live", name, "cert.pem")
	if v := sections[""]["cert"]; len(v) == 1 {
		certPath = v[0]
	}
	cert, err := readCert(certPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certPath, err)
	}
	if cert != nil {
		cur.domains, cur.notAfter = cert.DNSNames, cert.NotAfter
	}
	return cur, nil
}

// readCert returns the certificate in the PEM file p, or nil when p does not
// exist.
func readCert(p string) (*x509.Certificate, error) {
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// changes returns the plan lines of the step on the certificate cur, nil when
// it matches. A nil cur is a new certificate.
func (c *Certbot) changes(cur *certState) []string {
	if cur == nil {
		lines := []string{"domains " + strings.Join(c.Domains, ", ")}
		for _, s := range c.settings() {
			if s.value != "" && s != (setting{"reuse_key", "false"}) {
				lines = append(lines, s.key+settingValue(s.value))
			}
		}
		return lines
	}
	var lines []string
	if !sameSet(cur.domains, c.Domains) {
		lines = append(lines, "domains "+orNone(strings.Join(cur.domains, ", "))+" → "+strings.Join(c.Domains, ", "))
	}
	for _, s := range c.settings() {
		old := cur.settings[s.key]
		if old != s.value && strings.HasSuffix(s.key, "_hook") {
			old = unwrappedCertbotHook(old)
		}
		if old == s.value {
			continue
		}
		lines = append(lines, s.key+" "+orNone(firstLine(old))+" →"+settingValue(orNone(s.value)))
	}
	if lines == nil {
		return nil
	}
	again := "issue the certificate again, with a new key"
	if c.ReuseKey {
		again = "issue the certificate again, with the same key"
	}
	var hooks []string
	for _, s := range c.settings() {
		if strings.HasSuffix(s.key, "_hook") && s.value != "" {
			hooks = append(hooks, s.key)
		}
	}
	if hooks != nil {
		again += "; run " + strings.Join(hooks, ", ")
	}
	return append(lines, again)
}

// settingValue is a setting after its key in a plan line. A value of several lines
// starts on the next line, so the plan shows it in full.
func settingValue(v string) string {
	v = strings.TrimSuffix(v, "\n")
	if strings.Contains(v, "\n") {
		return "\n" + v
	}
	return " " + v
}

// firstLine is the first line of s, and " ..." when it has more.
func firstLine(s string) string {
	first, rest, _ := strings.Cut(strings.TrimSuffix(s, "\n"), "\n")
	if rest != "" {
		return first + " ..."
	}
	return first
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

func (c *Certbot) Check(_ context.Context, _ *State, note func(string)) (Result, error) {
	res, err := c.check(letsencrypt, note)
	if err != nil || !c.issue {
		return res, err
	}
	res.MissingTools, err = c.missingTools()
	return res, err
}

// missingTools returns certbot and the plugin of the authenticator when the
// host lacks them.
func (c *Certbot) missingTools() ([]Tool, error) {
	var tools []Tool
	if _, err := exec.LookPath("certbot"); err != nil {
		tools = append(tools, Tool{Name: "certbot", Package: "certbot"})
	}
	if a := c.authenticator(); a == "nginx" || a == "apache" {
		plugin := "/usr/lib/python3/dist-packages/certbot_" + a
		_, err := os.Stat(plugin)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			tools = append(tools, Tool{Name: plugin, Package: "python3-certbot-" + a})
		case err != nil:
			return nil, err
		}
	}
	return tools, nil
}

// check checks the step in the certbot directory dir.
func (c *Certbot) check(dir string, note func(string)) (Result, error) {
	cur, err := readCertState(dir, c.Name)
	if err != nil {
		return Result{}, err
	}
	if cur != nil && cur.domains == nil {
		return Result{}, fmt.Errorf("certificate %s: %s exists, but its certificate does not; certbot would make a new certificate %s-0001 on each run; remove the rest with certbot delete --cert-name %s", c.Name, renewalPath(dir, c.Name), c.Name, c.Name)
	}
	if cur != nil && time.Until(cur.notAfter) < 14*24*time.Hour {
		note("the certificate " + c.Name + " expires on " + cur.notAfter.UTC().Format(time.DateOnly) + "; check its renewal")
	}
	changes := c.changes(cur)
	c.issue = changes != nil
	for _, hook := range c.PendingHooks {
		changes = append(changes, "pending "+hook)
	}
	switch {
	case changes == nil:
		return Result{Status: OK}, nil
	case cur == nil:
		return Result{Status: Change, Action: Create, Changes: changes}, nil
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

// args returns the arguments of certbot. --force-renewal makes certbot issue
// a certificate that is not due, and write the settings of this call to the
// renewal file.
func (c *Certbot) args() []string {
	// A value after "=" cannot read as an option, also when it starts
	// with "-".
	args := []string{"certonly", "--non-interactive", "--agree-tos", "--no-eff-email", "--email=" + c.Email, "--cert-name=" + c.Name, "--domains=" + strings.Join(c.Domains, ","), "--authenticator=" + c.authenticator()}
	if c.WebrootPath != "" {
		args = append(args, "--webroot-path="+c.WebrootPath)
	}
	for _, h := range []struct {
		flag string
		hook *string
	}{{"--pre-hook", c.PreHook}, {"--post-hook", c.PostHook}, {"--deploy-hook", c.DeployHook}} {
		if h.hook != nil {
			args = append(args, h.flag+"="+certbotHook(*h.hook))
		}
	}
	if c.ReuseKey {
		args = append(args, "--reuse-key")
	}
	return append(args, "--force-renewal")
}

// The quoting keeps triple quotes out of the hook: configobj ends a value of
// several lines at the first line with its triple quotes.
var (
	hookQuote   = strings.NewReplacer(`'`, `'"'"'`, `"`, `'\"'`)
	hookUnquote = strings.NewReplacer(`'"'"'`, `'`, `'\"'`, `"`)
)

func certbotHook(command string) string {
	return "sh -ec '" + hookQuote.Replace(command) + "'"
}

func unwrappedCertbotHook(hook string) string {
	command, ok := strings.CutPrefix(hook, "sh -ec '")
	if !ok {
		return hook
	}
	command, ok = strings.CutSuffix(command, "'")
	if !ok {
		return hook
	}
	command = hookUnquote.Replace(command)
	if command == "" || certbotHook(command) != hook {
		return hook
	}

	return command
}

// HooksToRun returns the hooks that apply runs: the pending hooks, and, when it
// issues, deploy_hook and post_hook. The helper records them as pending until
// apply ends, in case the run stops.
func (c *Certbot) HooksToRun() []string {
	hooks := slices.Clone(c.PendingHooks)
	if c.issue && c.DeployHook != nil && !slices.Contains(hooks, "deploy_hook") {
		hooks = append(hooks, "deploy_hook")
	}
	if c.issue && c.PostHook != nil && !slices.Contains(hooks, "post_hook") {
		hooks = append(hooks, "post_hook")
	}
	slices.Sort(hooks)
	return hooks
}

func (c *Certbot) Apply(ctx context.Context, _ func(string)) error {
	ctx, cancel := context.WithTimeoutCause(ctx, commandLimit, fmt.Errorf("no result after %s", commandLimit))
	defer cancel()
	if !c.issue {
		var errs []error
		for _, hook := range slices.Clone(c.PendingHooks) {
			command := c.DeployHook
			var env []string
			if hook == "post_hook" {
				command = c.PostHook
			} else {
				env = []string{"RENEWED_LINEAGE=" + path.Join(letsencrypt, "live", c.Name), "RENEWED_DOMAINS=" + strings.Join(c.Domains, " ")}
			}
			if command != nil {
				if err := shellLimit(ctx, *command, "/", env, nil, commandLimit, KillDelay); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", hook, err))
					continue
				}
			}
			c.PendingHooks = slices.DeleteFunc(c.PendingHooks, func(h string) bool { return h == hook })
		}
		return errors.Join(errs...)
	}
	cmd := exec.CommandContext(ctx, "certbot", c.args()...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := wait(ctx, cmd, KillDelay)
	output := out.String()
	pending := c.PendingHooks
	if err != nil {
		// A certbot that was killed after it saved the certificate may not
		// have run its hooks, and its output shows no hook failure.
		if cur, rerr := readCertState(letsencrypt, c.Name); rerr == nil && cur != nil && c.changes(cur) == nil {
			pending = c.HooksToRun()
		}
	}
	c.PendingHooks = pendingHooks(pending, output, err == nil)
	if err != nil {
		return failure("certbot certonly", err, output)
	}
	return hookFailure(output)
}

// pendingHooks returns the hooks that are pending after certbot ran with the
// output out: the hooks that failed, and, when certbot failed, the hooks that
// were pending before, as certbot may not have run them.
func pendingHooks(pending []string, out string, ok bool) []string {
	var failed []string
	for line := range strings.Lines(out) {
		if hook := failedCertbotHook(line); hook != "" {
			failed = append(failed, strings.ReplaceAll(hook, "-", "_"))
		}
	}
	var next []string
	for _, hook := range []string{"deploy_hook", "post_hook"} {
		if slices.Contains(failed, hook) || !ok && slices.Contains(pending, hook) {
			next = append(next, hook)
		}
	}
	return next
}

// hookFailure returns an error with certbot's lines about the hooks that
// failed, or nil when none failed. certbot exits 0 after a failed hook.
func hookFailure(out string) error {
	var lines []string
	failed, inHook := false, false
	for line := range strings.Lines(out) {
		line = strings.TrimSuffix(line, "\n")
		switch {
		case strings.HasPrefix(line, "Hook '"):
			inHook = true
			failed = failed || failedCertbotHook(line) != ""
		case !inHook || !strings.HasPrefix(line, " "):
			inHook = false
			continue
		}
		lines = append(lines, line)
	}
	if !failed {
		return nil
	}
	return errors.New("a hook failed:\n" + strings.Join(lines[max(0, len(lines)-10):], "\n"))
}

func failedCertbotHook(line string) string {
	hook, ok := strings.CutPrefix(line, "Hook '")
	if !ok {
		return ""
	}
	hook, _, ok = strings.Cut(hook, "' reported error code ")
	if !ok {
		return ""
	}
	return hook
}
