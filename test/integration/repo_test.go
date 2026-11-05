package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/vmtest"
)

// The lab's signed source. Its suite, the codename of the image, holds
// winch-signed.
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
	suite := osRelease().codename
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
		return &module.Repo{Name: "winch-signed", URL: signedURL, Suite: suite, Components: []string{"main"}, KeyData: vmtest.RepoKey}
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
			WantState: module.State{Sources: true},
			Unchanged: "[ ! -e " + signedFile + " ] && [ ! -e " + signedAsc + " ] && ! ls /var/lib/apt/lists/10.0.2.100_signed_* 2>/dev/null",
			After: "[ \"$(stat -c '%a %U %G' " + signedFile + " " + signedAsc + ")\" = \"$(printf '644 root root\\n644 root root')\" ] && " +
				"apt-cache policy winch-signed | grep -q 'Candidate: 1' && " + others,
		},
		{
			Name:      "the keyrings directory is missing",
			WantState: module.State{Sources: true},
			Setup:     "rmdir /etc/apt/keyrings",
			Args:      args(),
			Want: module.Result{Status: module.Change, Action: module.Create, Changes: []string{
				"create directory /etc/apt/keyrings (owner root, group root, mode 0755)",
				"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
			After: "[ \"$(stat -c '%a' /etc/apt/keyrings)\" = 755 ]",
		},
		{
			Name:      "change the suite",
			Setup:     signedSource("bookworm"),
			State:     module.State{IndexFresh: true, Refreshed: true},
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{signedFile + ": Suites bookworm → " + suite, refresh}},
			WantState: module.State{Sources: true},
		},
		{
			Name:      "change the url",
			Setup:     strings.Replace(signedSource(suite), "URIs: "+signedURL, "URIs: http://10.0.2.100:80/signed", 1) + " && apt-get update -q >/dev/null && ls /var/lib/apt/lists | grep -q '^10.0.2.100:80_signed_'",
			State:     module.State{IndexFresh: true},
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{signedFile + ": URIs http://10.0.2.100:80/signed → " + signedURL, refresh}},
			WantState: module.State{Sources: true},
			After:     "apt-cache policy winch-signed | grep -q 'Candidate: 1'",
		},
		{
			Name:      "a key file with mode 0600 refreshes nothing",
			Setup:     signedSource(suite) + " && chmod 600 " + signedAsc,
			State:     module.State{IndexFresh: true, Refreshed: true},
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{signedAsc + ": mode 0600 → 0644"}},
			WantState: module.State{IndexFresh: true, Refreshed: true},
		},
		{
			Name:      "another key",
			Setup:     signedSource(suite) + " && cat > " + signedAsc + " <<'EOF'\n" + string(otherKey) + "EOF",
			State:     module.State{IndexFresh: true},
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove key " + other + " winch test key <test@example.com>", keyLine, refresh}},
			WantState: module.State{Sources: true},
		},
		{
			Name:      "an immutable source file",
			Setup:     signedSource("bookworm") + " && chattr +i " + signedFile,
			Args:      args(),
			WantErr:   signedFile + " is immutable; chattr -i removes the flag",
			Unchanged: "grep -q bookworm " + signedFile,
		},
		{
			Name:    "an immutable key file with another mode",
			Setup:   signedSource(suite) + " && chmod 600 " + signedAsc + " && chattr +i " + signedAsc,
			Args:    args(),
			WantErr: signedAsc + " is immutable; chattr -i removes the flag",
		},
		{
			Name:    "an append-only key file with another key",
			Setup:   signedSource(suite) + " && cat > " + signedAsc + " <<'EOF'\n" + string(otherKey) + "EOF\nchattr +a " + signedAsc,
			Args:    args(),
			WantErr: signedAsc + " is append-only; chattr -a removes the flag",
		},
		{
			Name:  "immutable files that are as the step declares",
			Setup: signedSource(suite) + " && chattr +i " + signedFile + " " + signedAsc,
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
			WantState:    module.State{Sources: true},
			Args:         withOther(),
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, "add key " + other + " winch test key <test@example.com>", "create file " + signedFile + sourceAttrs, refresh}},
			WantApplyErr: "refresh the index of source winch-signed",
			After:        "[ ! -e " + signedFile + " ] && [ ! -e " + signedAsc + " ]",
			FixArgs:      args(),
		},
		{
			Name:         "a failed refresh puts the old files back",
			WantState:    module.State{Sources: true},
			Setup:        signedSource(suite) + " && mkdir /root/saved && cp " + signedFile + " " + signedAsc + " /root/saved/",
			Args:         withOther(),
			Want:         module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"remove key " + fpr + " winch test repository", "add key " + other + " winch test key <test@example.com>", refresh}},
			WantApplyErr: "refresh the index of source winch-signed",
			After:        "cmp " + signedFile + " /root/saved/winch-signed.sources && cmp " + signedAsc + " /root/saved/winch-signed.asc && " + others,
			FixArgs:      args(),
		},
		{
			Name:         "a source that apt cannot fetch",
			WantState:    module.State{Sources: true},
			Args:         &module.Repo{Name: "winch-signed", URL: "http://127.0.0.1:9/down", Suite: suite, Components: []string{"main"}},
			Want:         module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedFile + sourceAttrs, refresh}},
			WantApplyErr: "refresh the index of source winch-signed",
			After:        "[ ! -e " + signedFile + " ]",
			FixArgs:      args(),
		},
		{
			Name:    "the source in another file",
			Setup:   "echo 'deb [signed-by=/usr/share/keyrings/x.gpg] " + signedURL + "/ " + suite + " main' > /etc/apt/sources.list.d/vendor.list",
			Args:    args(),
			WantErr: "the source " + signedURL + " " + suite + " is also in /etc/apt/sources.list.d/vendor.list; remove it there",
		},
		{
			Name:    "the source in another file that is a symbolic link",
			Setup:   "echo 'deb [signed-by=/usr/share/keyrings/x.gpg] " + signedURL + "/ " + suite + " main' > /root/saved && ln -s /root/saved /etc/apt/sources.list.d/vendor.list",
			Args:    args(),
			WantErr: "the source " + signedURL + " " + suite + " is also in /etc/apt/sources.list.d/vendor.list; remove it there",
		},
		{
			Name:      "an old key file that holds no key",
			Setup:     signedSource(suite) + " && echo 'not a key' > " + signedAsc,
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"replace " + signedAsc + ": is not an ASCII-armored OpenPGP public key", keyLine, refresh}},
			WantState: module.State{Sources: true},
		},
		{
			Name:    "an old source file larger than 1 MiB",
			Setup:   "head -c 1100000 /dev/zero | tr '\\0' '#' > " + signedFile,
			Args:    args(),
			WantErr: signedFile + " is larger than 1 MiB",
		},
		{
			Name:    "the source in sources.list",
			Setup:   "echo 'deb " + signedURL + " " + suite + " main' >> /etc/apt/sources.list",
			Args:    args(),
			WantErr: "the source " + signedURL + " " + suite + " is also in /etc/apt/sources.list; remove it there",
		},
		{
			Name:      "apt does not read a backup file",
			WantState: module.State{Sources: true},
			Setup:     "echo 'deb " + signedURL + " " + suite + " main' > /etc/apt/sources.list.d/vendor.list.save",
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
		},
		{
			Name:      "apply waits for the lock of the index",
			WantState: module.State{Sources: true},
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
			// The fcntl lock of apt; flock(1) takes a lock that apt does not see.
			BeforeApply: `(python3 -c 'import fcntl, time; f = open("/var/lib/apt/lists/lock", "w"); fcntl.lockf(f, fcntl.LOCK_EX); open("/root/locked", "w"); time.sleep(3)' >/dev/null 2>&1 &) && ` +
				"timeout 10 sh -c 'until [ -e /root/locked ]; do sleep 0.1; done'",
			After: "! pgrep -f 'fcntl[.]lockf'",
		},
		{
			Name:      "a disabled source in another file",
			WantState: module.State{Sources: true},
			Setup:     "printf 'Types: deb\\nURIs: " + signedURL + "\\nSuites: " + suite + "\\nComponents: main\\nEnabled: no\\n' > /etc/apt/sources.list.d/vendor.sources",
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
		},
		{
			Name:      "a deb-src entry in another file",
			WantState: module.State{Sources: true},
			Setup:     "echo 'deb-src " + signedURL + " " + suite + " main' > /etc/apt/sources.list.d/vendor.list",
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
		},
		{
			Name:      "a directory with the name of a sources file",
			WantState: module.State{Sources: true},
			Setup:     "mkdir /etc/apt/sources.list.d/vendor.list",
			Args:      args(),
			Want:      module.Result{Status: module.Change, Action: module.Create, Changes: []string{"create file " + signedAsc + sourceAttrs, keyLine, "create file " + signedFile + sourceAttrs, refresh}},
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
	suite := osRelease().codename
	vm.MustRun(t, "echo 'deb [signed-by=/usr/share/keyrings/x.gpg] "+signedURL+" "+suite+" main' > /etc/apt/sources.list.d/vendor.list")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  repo-absent: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: apt\n    hosts: all\n    steps:\n      - recipe: signed\n",
		"recipes/signed/recipe.yaml": `steps:
  - file:
      path: /etc/apt/sources.list.d/vendor.list
      absent: true
  - repo:
      name: winch-signed
      url: ` + signedURL + `
      suite: ` + suite + `
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

// spec: Remote execution/Helper; Modules/repo; Modules/pkg
func TestMirrorSource(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "mirror")
	// Debian's cloud images list their mirrors in a file, as here.
	vm.MustRun(t, "mkdir -p /etc/apt/mirrors && echo http://10.0.2.100/test/ > /etc/apt/mirrors/winch-test.list && "+
		"sed -i 's|^URIs: .*|URIs: mirror+file:///etc/apt/mirrors/winch-test.list|' /etc/apt/sources.list.d/winch-test.sources")
	dir := vmtest.WriteProject(t, map[string]string{
		"winch.yaml":            "name: demo\ninventory: test\n",
		"inventories/test.yaml": "hosts:\n  mirror: {}\n",
		"pipelines/site.yaml":   "stages:\n  - name: apt\n    hosts: all\n    steps:\n      - recipe: signed\n",
		"recipes/signed/recipe.yaml": `steps:
  - repo:
      name: winch-signed
      url: ` + signedURL + `
      suite: ` + osRelease().codename + `
      components: [main]
      key: signed.asc
  - pkg:
      name: winch-signed
`,
		"recipes/signed/files/signed.asc": string(vmtest.RepoKey),
	})
	// Each plan refreshes winch's index with the planned sources.
	for i := range 2 {
		if r := lab.Winch(t, dir, "plan", "site"); r.Code != 0 || !strings.Contains(r.Stdout, "+ pkg winch-signed") {
			t.Fatalf("plan %d: exit %d, stdout %q, stderr %q", i+1, r.Code, r.Stdout, r.Stderr)
		}
	}
	vm.MustRun(t, "[ -L /var/lib/winch/apt/lists/auxfiles/_etc_apt_mirrors_winch-test.list ]")
	if r := lab.Winch(t, dir, "apply", "site", "--yes"); r.Code != 0 {
		t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
	vm.MustRun(t, "dpkg -s winch-signed >/dev/null")
	vm.MustRun(t, "chown -h nobody /var/lib/winch/apt/lists/auxfiles/_etc_apt_mirrors_winch-test.list")
	if r := lab.Winch(t, dir, "plan", "site"); r.Code == 0 || !strings.Contains(r.Stderr, "/var/lib/winch/apt/lists/auxfiles/_etc_apt_mirrors_winch-test.list is not owned by root") {
		t.Fatalf("plan with a link of another user: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}

// oldSigned serves version 0 of winch-signed, which depends on winch-up-new,
// from a local file: source. The lab's signed source has version 1, which
// does not.
const oldSigned = `set -e
mkdir -p /srv/old/winch-signed/DEBIAN
printf 'Package: winch-signed\nVersion: 0\nArchitecture: all\nMaintainer: winch\nDepends: winch-up-new\nDescription: test\n' > /srv/old/winch-signed/DEBIAN/control
cd /srv/old
dpkg-deb -b winch-signed winch-signed_0_all.deb >/dev/null
{ dpkg-deb -f winch-signed_0_all.deb; echo "Filename: ./winch-signed_0_all.deb"; echo "Size: $(stat -c %s winch-signed_0_all.deb)"; echo "SHA256: $(sha256sum winch-signed_0_all.deb | cut -d' ' -f1)"; } > Packages
echo 'deb [trusted=yes] file:/srv/old ./' > /etc/apt/sources.list.d/old.list
apt-get update -q >/dev/null`

// spec: Modules/pkg; Modules/repo; Modules/upgrade
func TestPlanAfterRepo(t *testing.T) {
	t.Parallel()
	vm := lab.StartVM(t, "repo-plan")
	vm.MustRun(t, "rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list.d/winch-debian.sources && apt-get update -q >/dev/null && "+oldSigned)
	suite := osRelease().codename
	repo := func(name, url string) string {
		return "  - repo:\n      name: " + name + "\n      url: " + url + "\n      suite: " + suite + "\n      components: [main]\n      key: signed.asc\n"
	}
	project := func(steps ...string) string {
		return vmtest.WriteProject(t, map[string]string{
			"winch.yaml":                      "name: demo\ninventory: test\n",
			"inventories/test.yaml":           "hosts:\n  repo-plan: {}\n",
			"pipelines/site.yaml":             "stages:\n  - name: apt\n    hosts: all\n    steps:\n      - recipe: signed\n",
			"recipes/signed/recipe.yaml":      "steps:\n" + strings.Join(steps, ""),
			"recipes/signed/files/signed.asc": string(vmtest.RepoKey),
		})
	}
	reset := "dpkg --purge winch-signed winch-up-new >/dev/null; rm -f /etc/apt/sources.list.d/winch-* /etc/apt/keyrings/winch-* /etc/apt/sources.list /etc/apt/sources.list.d/stale.list && " +
		"printf 'Types: deb\\nURIs: http://10.0.2.100/test/\\nSuites: ./\\nTrusted: yes\\n' > /etc/apt/sources.list.d/winch-test.sources && apt-get update -q >/dev/null"
	// stale lists the signed source with another key, which apt refuses next
	// to the step's source.
	stale := "deb [signed-by=/etc/apt/keyrings/stale.asc] " + signedURL + " " + suite + " main"
	absent := func(p string) string { return "  - file:\n      path: " + p + "\n      absent: true\n" }
	const apt = "find /etc/apt /var/lib/apt/lists -printf '%p %s %T@ %m\\n' | sort"

	t.Run("pkg", func(t *testing.T) {
		vm.MustRun(t, reset+" && DEBIAN_FRONTEND=noninteractive apt-get install -y -q winch-up-new >/dev/null")
		dir := project(repo("winch-signed", signedURL), "  - pkg:\n      name: winch-signed\n", "  - pkg:\n      name: winch-up-new\n      absent: true\n")
		before := vm.MustRun(t, apt)
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, "install winch-signed") || !strings.Contains(r.Stdout, "remove winch-up-new") ||
			strings.Contains(r.Stdout, "also") || strings.Contains(r.Stdout, module.OthersUnknown) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q, want winch-signed 1, which needs no winch-up-new", r.Code, r.Stdout, r.Stderr)
		}
		if after := vm.MustRun(t, apt); after != before {
			t.Errorf("the plan changed apt's files:\nbefore:\n%s\nafter:\n%s", before, after)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, version("winch-signed", "1")+" && ! dpkg -s winch-up-new >/dev/null 2>&1")
		r = lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, ": 0 to change,") {
			t.Errorf("second plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})

	t.Run("upgrade", func(t *testing.T) {
		vm.MustRun(t, reset+" && DEBIAN_FRONTEND=noninteractive apt-get install -y -q winch-signed=0 >/dev/null")
		dir := project(repo("winch-signed", signedURL), "  - upgrade:\n      mode: safe\n")
		r := lab.Winch(t, dir, "plan", "site")
		if r.Code != 0 || !strings.Contains(r.Stdout, "upgrade winch-signed 0 → 1") {
			t.Errorf("plan: exit %d, stdout %q, stderr %q, want the upgrade of winch-signed", r.Code, r.Stdout, r.Stderr)
		}
		r = lab.Winch(t, dir, "apply", "site", "--yes")
		if r.Code != 0 {
			t.Fatalf("apply: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
		vm.MustRun(t, version("winch-signed", "1"))
	})

	t.Run("a removed sources.list", func(t *testing.T) {
		vm.MustRun(t, reset+" && echo '"+stale+"' > /etc/apt/sources.list")
		r := lab.Winch(t, project(absent("/etc/apt/sources.list"), repo("winch-signed", signedURL), "  - pkg:\n      name: winch-signed\n"), "plan", "site")
		if r.Code != 0 {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})

	t.Run("a source that a step between two repo steps removes", func(t *testing.T) {
		vm.MustRun(t, reset+" && echo '"+stale+"' > /etc/apt/sources.list.d/stale.list")
		r := lab.Winch(t, project(repo("winch-signed80", "http://10.0.2.100:80/signed"), absent("/etc/apt/sources.list.d/stale.list"), repo("winch-signed", signedURL), "  - pkg:\n      name: winch-signed\n"), "plan", "site")
		if r.Code != 0 {
			t.Errorf("plan: exit %d, stdout %q, stderr %q", r.Code, r.Stdout, r.Stderr)
		}
	})

	t.Run("a source that apt cannot fetch", func(t *testing.T) {
		vm.MustRun(t, reset)
		r := lab.Winch(t, project(repo("winch-signed", "http://127.0.0.1:9/down"), "  - pkg:\n      name: winch-up-new\n"), "plan", "site")
		if want := "refresh the index of the sources that the run will have"; r.Code == 0 || !strings.Contains(r.Stderr, want) {
			t.Errorf("plan: exit %d, stdout %q, stderr %q, want an error with %q", r.Code, r.Stdout, r.Stderr, want)
		}
	})
}
