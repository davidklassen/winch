package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// The lab's signed source. Its suite trixie holds winch-signed.
const (
	signedURL   = "http://10.0.2.100/signed"
	signedFile  = "/etc/apt/sources.list.d/winch-signed.sources"
	signedAsc   = "/etc/apt/keyrings/winch-signed.asc"
	sourceAttrs = " (owner root, group root, mode 0644)"
)

// signedSource writes the source file of the signed source with suite, and
// its key.
func signedSource(suite string) string {
	return "cat > " + signedAsc + " <<'EOF'\n" + string(vmtest.RepoKey) + "EOF\nprintf 'Types: deb\\nURIs: " + signedURL +
		"\\nSuites: " + suite + "\\nComponents: main\\nSigned-By: " + signedAsc + "\\n' > " + signedFile
}

// spec: Modules/repo; Modules/pkg
func TestRepoModule(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "repo")
	// The index of the lab's other sources, which a repo step keeps.
	vm.MustRun(t, "apt-get update -q >/dev/null")
	const others = "ls /var/lib/apt/lists | grep -q '^10.0.2.100_debian_'"
	const (
		fpr   = "C19F7BA4735783E4167DC2AA4B7ED2E367468894"
		other = "08F59DAD86F61D67A6A960698445EE6567433B2C"
	)
	otherKey, err := os.ReadFile("../../internal/module/testdata/key.asc")
	if err != nil {
		t.Fatal(err)
	}
	args := func() *module.Repo {
		return &module.Repo{Name: "winch-signed", URL: signedURL, Suite: "trixie", Components: []string{"main"}, KeyData: vmtest.RepoKey}
	}
	refresh := "refresh the index of source winch-signed"
	keyLine := "add key " + fpr + " winch test repository"
	reset := "pkill -f 'fcntl[.]lockf'; chattr -ia " + signedFile + " " + signedAsc + " 2>/dev/null; rm -f " + signedFile + " " + signedAsc + " /etc/apt/sources.list.d/vendor.* /var/lib/apt/lists/10.0.2.100_signed_* /var/lib/apt/lists/10.0.2.100:80_signed_* /root/locked; " +
		"rm -rf /etc/apt/sources.list.d/vendor.list /etc/apt/sources.list.d/debian.sources; sed -i '/10.0.2.100.signed/d' /etc/apt/sources.list 2>/dev/null; rm -rf /root/saved; mkdir -p /etc/apt/keyrings"
	withOther := func() *module.Repo {
		r := args()
		r.KeyData = otherKey
		return r
	}
	vmtest.RunCases(t, vm, "repo", reset, []vmtest.Case{
		{
			Name:      "create with a key",
			State:     module.State{IndexFresh: true},
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
			WantState: module.State{},
			Unchanged: "[ ! -e " + signedFile + " ] && [ ! -e " + signedAsc + " ] && ! ls /var/lib/apt/lists/10.0.2.100_signed_* 2>/dev/null",
			After: "[ \"$(stat -c '%a %U %G' " + signedFile + " " + signedAsc + ")\" = \"$(printf '644 root root\\n644 root root')\" ] && " +
				"apt-cache policy winch-signed | grep -q 'Candidate: 1' && " + others,
		},
		{
			Name:  "the keyrings directory is missing",
			Setup: "rmdir /etc/apt/keyrings",
			Args:  args(),
			Want: module.Result{Status: module.Change, Action: module.Create, Changes: []string{
				"create directory /etc/apt/keyrings (owner root, group root, mode 0755)",
				"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
			After: "[ \"$(stat -c '%a' /etc/apt/keyrings)\" = 755 ]",
		},
		{
			Name:      "change the suite",
			Setup:     signedSource("bookworm"),
			State:     module.State{IndexFresh: true},
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{signedFile + ": Suites bookworm → trixie", refresh}},
			WantState: module.State{},
		},
		{
			Name:      "change the url",
			Setup:     strings.Replace(signedSource("trixie"), "URIs: "+signedURL, "URIs: http://10.0.2.100:80/signed", 1) + " && apt-get update -q >/dev/null && ls /var/lib/apt/lists | grep -q '^10.0.2.100:80_signed_'",
			State:     module.State{IndexFresh: true},
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{signedFile + ": URIs http://10.0.2.100:80/signed → " + signedURL, refresh}},
			WantState: module.State{},
			After:     "apt-cache policy winch-signed | grep -q 'Candidate: 1'",
		},
		{
			Name:      "a key file with mode 0600 refreshes nothing",
			Setup:     signedSource("trixie") + " && chmod 600 " + signedAsc,
			State:     module.State{IndexFresh: true},
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{signedAsc + ": mode 0600 → 0644"}},
			WantState: module.State{IndexFresh: true},
		},
		{
			Name:      "another key",
			Setup:     signedSource("trixie") + " && cat > " + signedAsc + " <<'EOF'\n" + string(otherKey) + "EOF",
			State:     module.State{IndexFresh: true},
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove key " + other + " winch test key <test@example.com>", keyLine, refresh}},
			WantState: module.State{},
		},
		{
			Name:      "an immutable source file",
			Setup:     signedSource("bookworm") + " && chattr +i " + signedFile,
			Args:      args(),
			WantErr:   signedFile + " is immutable; chattr -i changes it",
			Unchanged: "grep -q bookworm " + signedFile,
		},
		{
			Name:    "an immutable key file with another mode",
			Setup:   signedSource("trixie") + " && chmod 600 " + signedAsc + " && chattr +i " + signedAsc,
			Args:    args(),
			WantErr: signedAsc + " is immutable; chattr -i changes it",
		},
		{
			Name:    "an append-only key file with another key",
			Setup:   signedSource("trixie") + " && cat > " + signedAsc + " <<'EOF'\n" + string(otherKey) + "EOF\nchattr +a " + signedAsc,
			Args:    args(),
			WantErr: signedAsc + " is append-only; chattr -a changes it",
		},
		{
			Name:  "immutable files that are as the step declares",
			Setup: signedSource("trixie") + " && chattr +i " + signedFile + " " + signedAsc,
			Args:  args(),
			Want:  module.Result{Status: module.OK},
		},
		{
			Name:    "a flat source that the test source has already",
			Args:    &module.Repo{Name: "winch-signed", URL: "http://10.0.2.100/test", Suite: "./"},
			WantErr: "the source http://10.0.2.100/test ./ is also in /etc/apt/sources.list.d/winch-test.sources; remove it there",
		},
		{
			Name:         "a key that does not sign the source",
			Args:         withOther(),
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, "add key " + other + " winch test key <test@example.com>", "create file " + signedFile + sourceAttrs, refresh}},
			WantApplyErr: "refresh the index of source winch-signed",
			After:        "[ ! -e " + signedFile + " ] && [ ! -e " + signedAsc + " ]",
			FixArgs:      args(),
		},
		{
			Name:         "a failed refresh puts the old files back",
			Setup:        signedSource("trixie") + " && mkdir /root/saved && cp " + signedFile + " " + signedAsc + " /root/saved/",
			Args:         withOther(),
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove key " + fpr + " winch test repository", "add key " + other + " winch test key <test@example.com>", refresh}},
			WantApplyErr: "refresh the index of source winch-signed",
			After:        "cmp " + signedFile + " /root/saved/winch-signed.sources && cmp " + signedAsc + " /root/saved/winch-signed.asc && " + others,
			FixArgs:      args(),
		},
		{
			Name:         "a source that apt cannot fetch",
			Args:         &module.Repo{Name: "winch-signed", URL: "http://127.0.0.1:9/down", Suite: "trixie", Components: []string{"main"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedFile + sourceAttrs, refresh}},
			WantApplyErr: "refresh the index of source winch-signed",
			After:        "[ ! -e " + signedFile + " ]",
			FixArgs:      args(),
		},
		{
			Name:    "the source in another file",
			Setup:   "echo 'deb [signed-by=/usr/share/keyrings/x.gpg] " + signedURL + "/ trixie main' > /etc/apt/sources.list.d/vendor.list",
			Args:    args(),
			WantErr: "the source " + signedURL + " trixie is also in /etc/apt/sources.list.d/vendor.list; remove it there",
		},
		{
			Name:      "an old key file that holds no key",
			Setup:     signedSource("trixie") + " && echo 'not a key' > " + signedAsc,
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"replace " + signedAsc + ": is not an ASCII-armored OpenPGP public key", keyLine, refresh}},
			WantState: module.State{},
		},
		{
			Name:    "an old source file larger than 1 MiB",
			Setup:   "head -c 1100000 /dev/zero | tr '\\0' '#' > " + signedFile,
			Args:    args(),
			WantErr: signedFile + " is larger than 1 MiB",
		},
		{
			Name:    "the source in sources.list",
			Setup:   "echo 'deb " + signedURL + " trixie main' >> /etc/apt/sources.list",
			Args:    args(),
			WantErr: "the source " + signedURL + " trixie is also in /etc/apt/sources.list; remove it there",
		},
		{
			Name:  "apt does not read a backup file",
			Setup: "echo 'deb " + signedURL + " trixie main' > /etc/apt/sources.list.d/vendor.list.save",
			Args:  args(),
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
		},
		{
			Name: "apply waits for the lock of the index",
			Args: args(),
			Want: module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
			// The fcntl lock of apt; flock(1) takes a lock that apt does not see.
			BeforeApply: `(python3 -c 'import fcntl, time; f = open("/var/lib/apt/lists/lock", "w"); fcntl.lockf(f, fcntl.LOCK_EX); open("/root/locked", "w"); time.sleep(3)' >/dev/null 2>&1 &) && ` +
				"timeout 10 sh -c 'until [ -e /root/locked ]; do sleep 0.1; done'",
			After: "! pgrep -f 'fcntl[.]lockf'",
		},
		{
			Name:  "a disabled source in another file",
			Setup: "printf 'Types: deb\\nURIs: " + signedURL + "\\nSuites: trixie\\nComponents: main\\nEnabled: no\\n' > /etc/apt/sources.list.d/vendor.sources",
			Args:  args(),
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
		},
		{
			Name:  "a deb-src entry in another file",
			Setup: "echo 'deb-src " + signedURL + " trixie main' > /etc/apt/sources.list.d/vendor.list",
			Args:  args(),
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
		},
		{
			Name:  "a directory with the name of a sources file",
			Setup: "mkdir /etc/apt/sources.list.d/vendor.list",
			Args:  args(),
			Want:  module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
		},
		{
			Name:    "the image's debian.sources at the step's path",
			Setup:   "cat > /etc/apt/sources.list.d/debian.sources <<'EOF'\n" + imageSources + "EOF",
			Args:    &module.Repo{Name: "debian", URL: "http://deb.debian.org/debian", Suite: "trixie", Components: []string{"main"}},
			WantErr: "/etc/apt/sources.list.d/debian.sources holds deb mirror+file:///etc/apt/mirrors/debian.list trixie, which is not this step's source; move it to another file",
		},
	})
}

// The /etc/apt/sources.list.d/debian.sources of the Debian cloud image.
const imageSources = `Types: deb deb-src
URIs: mirror+file:///etc/apt/mirrors/debian.list
Suites: trixie trixie-updates trixie-backports
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb deb-src
URIs: mirror+file:///etc/apt/mirrors/debian-security.list
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
`

// spec: Modules/repo
func TestRepoAfterAbsentStep(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "repo-absent")
	vm.MustRun(t, "echo 'deb [signed-by=/usr/share/keyrings/x.gpg] "+signedURL+" trixie main' > /etc/apt/sources.list.d/vendor.list")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: inventories/test.yaml\n",
		"inventories/test.yaml": "hosts:\n  repo-absent: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: apt\n    hosts: all\n    steps:\n      - recipe: signed\n",
		"recipes/signed/recipe.yaml": `steps:
  - file:
      path: /etc/apt/sources.list.d/vendor.list
      absent: true
  - repo:
      name: winch-signed
      url: ` + signedURL + `
      suite: trixie
      components: [main]
      key: signed.asc
`,
		"recipes/signed/files/signed.asc": string(vmtest.RepoKey),
	})
	r := lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !strings.Contains(r.Stdout, "+ repo winch-signed") {
		t.Fatalf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	r = lab.Winch(t, dir, "apply", "site", "--yes")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, "[ ! -e /etc/apt/sources.list.d/vendor.list ] && apt-cache policy winch-signed | grep -q 'Candidate: 1'")
	r = lab.Winch(t, dir, "plan", "site")
	if r.Code != 0 || !unchanged(r.Stdout, 1) {
		t.Errorf("second plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}
