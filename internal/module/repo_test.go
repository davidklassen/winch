package module

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// spec: Modules/repo
func TestRepoValidate(t *testing.T) {
	const base = "url: https://rspamd.com/apt-stable\nsuite: trixie\ncomponents: [main]\n"
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"all fields", "name: rspamd\n" + base + "key: keys/rspamd.asc\n", ""},
		{"no key", "name: backports\nurl: http://deb.debian.org/debian\nsuite: trixie-backports\ncomponents: [main, contrib]\n", ""},
		{"one component", "name: a\nurl: https://example.com/apt\nsuite: trixie\ncomponents: main\n", ""},
		{"flat", "name: a\nurl: https://example.com/apt\nsuite: ./\n", ""},
		{"dots and digits", "name: example.com_2-x\n" + base, ""},
		{"no name", base, `t.yaml:1:1: missing key "name"`},
		{"bad name", "name: a/b\n" + base, `t.yaml:1:7: name: "a/b" is not a source name; a name has letters, digits, "_", "-", and ".", and does not start with "."`},
		{"hidden name", "name: .a\n" + base, `t.yaml:1:7: name: ".a" is not a source name; a name has letters, digits, "_", "-", and ".", and does not start with "."`},
		{"no url", "name: a\nsuite: trixie\ncomponents: [main]\n", `t.yaml:1:1: missing key "url"`},
		{"ftp url", "name: a\nurl: ftp://example.com/apt\nsuite: trixie\ncomponents: [main]\n", `t.yaml:2:6: url: must start with http:// or https://`},
		{"no host", "name: a\nurl: https:///apt\nsuite: trixie\ncomponents: [main]\n", `t.yaml:2:6: url: has no host`},
		{"user info", "name: a\nurl: https://u:p@example.com/apt\nsuite: trixie\ncomponents: [main]\n", `t.yaml:2:6: url: holds a user name or password, and the source file is world-readable; put them in /etc/apt/auth.conf.d/a.conf with mode 0600`},
		{"space in url", "name: a\nurl: https://example.com/a b\nsuite: trixie\ncomponents: [main]\n", `t.yaml:2:6: url: has white space or a control character`},
		{"control in url", "name: a\nurl: \"https://example.com/a\\x01\"\nsuite: trixie\ncomponents: [main]\n", `t.yaml:2:6: url: has white space or a control character`},
		{"empty suite", "name: a\nurl: https://example.com/apt\nsuite: \"\"\ncomponents: [main]\n", `t.yaml:3:8: suite: is empty`},
		{"control in component", "name: a\nurl: https://example.com/apt\nsuite: trixie\ncomponents: [\"ma\\x01in\"]\n", `t.yaml:4:13: components: element 1 has white space or a control character`},
		{"space in suite", "name: a\nurl: https://example.com/apt\nsuite: trixie main\ncomponents: [main]\n", `t.yaml:3:8: suite: has white space or a control character`},
		{"newline in suite", "name: a\nurl: https://example.com/apt\nsuite: \"trixie\\nmain\"\ncomponents: [main]\n", `t.yaml:3:8: suite: has white space or a control character`},
		{"space in component", "name: a\nurl: https://example.com/apt\nsuite: trixie\ncomponents: [main, \"non free\"]\n", `t.yaml:4:13: components: element 2 has white space or a control character`},
		{"no components", "name: a\nurl: https://example.com/apt\nsuite: trixie\n", `t.yaml:3:8: suite: needs components, such as [main]; only a flat suite, which ends in "/", has none`},
		{"empty components", "name: a\nurl: https://example.com/apt\nsuite: trixie\ncomponents: []\n", `t.yaml:3:8: suite: needs components, such as [main]; only a flat suite, which ends in "/", has none`},
		{"flat with components", "name: a\nurl: https://example.com/apt\nsuite: ./\ncomponents: [main]\n", `t.yaml:4:13: components: a flat suite, which ends in "/", has no components`},
		{"key outside files", "name: a\n" + base + "key: ../rspamd.asc\n", `t.yaml:5:6: key: must be a clean relative path, such as "a/b.conf"`},
		{"absolute key", "name: a\n" + base + "key: /etc/rspamd.asc\n", `t.yaml:5:6: key: must be a clean relative path, such as "a/b.conf"`},
		{"unknown key", "name: a\n" + base + "keyring: x\n", `t.yaml:5:1: unknown key "keyring"`},
		{"absent", "name: a\n" + base + "absent: true\n", `t.yaml:5:1: unknown key "absent"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { validate(t, &Repo{}, tt.yaml, tt.want) })
	}
}

// spec: Modules/repo
func TestRepoSource(t *testing.T) {
	tests := []struct {
		name string
		repo Repo
		want string
	}{
		{"key", Repo{Name: "rspamd", URL: "https://rspamd.com/apt-stable", Suite: "trixie", Components: []string{"main", "contrib"}, KeyData: []byte("key")},
			"Types: deb\nURIs: https://rspamd.com/apt-stable\nSuites: trixie\nComponents: main contrib\nSigned-By: /etc/apt/keyrings/rspamd.asc\n"},
		{"no key", Repo{Name: "bp", URL: "http://deb.debian.org/debian", Suite: "trixie-backports", Components: []string{"main"}},
			"Types: deb\nURIs: http://deb.debian.org/debian\nSuites: trixie-backports\nComponents: main\n"},
		{"flat", Repo{Name: "f", URL: "http://example.com/flat", Suite: "./"},
			"Types: deb\nURIs: http://example.com/flat\nSuites: ./\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.repo.source()); got != tt.want {
				t.Errorf("source =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

const (
	testFpr     = "08F59DAD86F61D67A6A960698445EE6567433B2C"
	rsaFpr      = "68211508469BEE79A13385E5EE1E5094B9E465ED"
	expiringFpr = "98E68808D2F3430CFF79D49BADF72694C8CF341E"
	// subkey-expired.asc and subkey-renewed.asc: a primary key that only
	// certifies, and a signing subkey.
	subPrimaryFpr = "6106974DDD1D043FCDB2370EEAAFB33105B1B0C4"
	subFpr        = "D7930139E249DA499CA8A969B26122648A0487A5"
)

// spec: Modules/repo
func TestParsePGPKeys(t *testing.T) {
	testKey := pgpKey{fingerprint: testFpr, userID: "winch test key <test@example.com>", signs: true}
	rsaKey := pgpKey{fingerprint: rsaFpr, userID: "winch rsa key <rsa@example.com>", signs: true}
	expiring := pgpKey{fingerprint: expiringFpr, userID: "winch expiring key <expiring@example.com>", signs: true}
	expiringAt := func(t time.Time) pgpKey {
		k := expiring
		k.expires = t
		return k
	}
	tests := []struct {
		file    string
		want    []pgpKey
		wantErr string
	}{
		{"key.asc", []pgpKey{testKey}, ""},
		{"rsa.asc", []pgpKey{rsaKey}, ""},
		{"expiring.asc", []pgpKey{expiringAt(time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC))}, ""},
		{"renewed.asc", []pgpKey{expiringAt(time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))}, ""},
		{"two-keys.asc", []pgpKey{testKey, rsaKey}, ""},
		{"two-blocks.asc", []pgpKey{testKey, rsaKey}, ""},
		{"key.gpg", nil, "is not an ASCII-armored OpenPGP public key"},
		{"signature.asc", nil, "is not an ASCII-armored OpenPGP public key"},
		{"revoked.asc", nil, "the key 06AC54F1582AD1504107DE2CD1EAA49074573A45 is revoked"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got, err := parsePGPKeys(readTestdata(t, tt.file))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for i := range got {
				got[i].data = ""
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parsePGPKeys = %+v; want %+v", got, tt.want)
			}
		})
	}
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// testSig is a test signature on the user ID: its creation time, the key
// lifetime in days, and the issuer, nil for the key itself.
type testSig struct {
	created  time.Time
	lifetime int
	issuer   []byte
}

// buildKey returns an armored key created at 2024-01-01 with the signatures
// sigs, and its fingerprint. The signatures are not valid.
func buildKey(sigs ...testSig) ([]byte, string) {
	created := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	be32 := func(v int64) []byte { return binary.BigEndian.AppendUint32(nil, uint32(v)) }
	packet := func(tag byte, body []byte) []byte { return append([]byte{0xc0 | tag, byte(len(body))}, body...) }
	key := append(append([]byte{4}, be32(created.Unix())...), 22, 1, 2, 3)
	fpr := sha1.Sum(append([]byte{0x99, 0, byte(len(key))}, key...))
	data := append(packet(tagPublicKey, key), packet(tagUserID, []byte("a <a@example.com>"))...)
	for _, s := range sigs {
		issuer := s.issuer
		if issuer == nil {
			issuer = fpr[:]
		}
		hashed := append([]byte{5, subCreated}, be32(s.created.Unix())...)
		hashed = append(append(hashed, 5, subExpires), be32(int64(s.lifetime)*86400)...)
		hashed = append(append(hashed, 22, subIssuerFpr, 4), issuer...)
		sig := append([]byte{4, sigCertPositive, 22, 8, 0, byte(len(hashed))}, hashed...)
		data = append(data, packet(tagSignature, append(sig, 0, 0, 0, 0))...)
	}
	return []byte(armorBegin + "\n\n" + base64.StdEncoding.EncodeToString(data) + "\n" + armorEnd + "\n"),
		strings.ToUpper(hex.EncodeToString(fpr[:]))
}

// spec: Modules/repo
func TestPGPKeyExpirySelfSig(t *testing.T) {
	jan, jun := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	old := testSig{created: jan, lifetime: 365}
	renewed := testSig{created: jun, lifetime: 1000}
	other := testSig{created: jun, lifetime: 0, issuer: make([]byte, 20)}
	tests := []struct {
		name string
		sigs []testSig
		want time.Time
	}{
		{"old then renewed", []testSig{old, renewed}, jan.AddDate(0, 0, 1000)},
		{"renewed then old", []testSig{renewed, old}, jan.AddDate(0, 0, 1000)},
		{"newer certification by another key", []testSig{old, other}, jan.AddDate(0, 0, 365)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := buildKey(tt.sigs...)
			keys, err := parsePGPKeys(data)
			if err != nil || len(keys) != 1 {
				t.Fatalf("parsePGPKeys = %d keys, %v; want 1 key", len(keys), err)
			}
			if !keys[0].expires.Equal(tt.want) {
				t.Errorf("expires = %v, want %v", keys[0].expires, tt.want)
			}
		})
	}
}

// spec: Modules/repo
func TestRepoSetKey(t *testing.T) {
	day := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 12, 0, 0, 0, time.UTC) }
	expiring := string(readTestdata(t, "expiring.asc"))
	renewed := string(readTestdata(t, "renewed.asc"))
	both := string(readTestdata(t, "key.asc")) + expiring
	subExpired := string(readTestdata(t, "subkey-expired.asc"))
	jan := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	april, aprilFpr := buildKey(testSig{created: jan, lifetime: 100})
	february, februaryFpr := buildKey(testSig{created: jan, lifetime: 400})
	tests := []struct {
		name, data string
		now        time.Time
		want       []string
		wantErr    string
	}{
		{"no expiry", string(readTestdata(t, "key.asc")), day(2100, 1, 1), nil, ""},
		{"expires later", expiring, day(2024, 6, 1), nil, ""},
		{"expires soon", expiring, day(2024, 12, 21), []string{"a.asc: the key " + expiringFpr + " expires on 2024-12-31"}, ""},
		{"expired", expiring, day(2025, 1, 1), nil, "a.asc: the key " + expiringFpr + " expired on 2024-12-31"},
		{"renewed", renewed, day(2025, 1, 1), nil, ""},
		{"second key expired", both, day(2025, 1, 1), []string{"a.asc: the key " + expiringFpr + " expired on 2024-12-31"}, ""},
		{"every key expired", expiring + string(april), day(2025, 1, 1), nil, "a.asc: the key " + expiringFpr + " expired on 2024-12-31; the key " + aprilFpr + " expired on 2024-04-10"},
		{"expired and expires soon", expiring + string(february), day(2025, 1, 10), []string{
			"a.asc: the key " + expiringFpr + " expired on 2024-12-31",
			"a.asc: the key " + februaryFpr + " expires on 2025-02-04",
		}, ""},
		{"second key expires soon", both, day(2024, 12, 21), []string{"a.asc: the key " + expiringFpr + " expires on 2024-12-31"}, ""},
		{"signing subkey expired", subExpired, day(2025, 3, 1), nil, "a.asc: the signing subkey " + subFpr + " of the key " + subPrimaryFpr + " expired on 2025-01-31"},
		{"signing subkey expires soon", subExpired, day(2025, 1, 20), []string{"a.asc: the signing subkey " + subFpr + " of the key " + subPrimaryFpr + " expires on 2025-01-31"}, ""},
		{"signing subkey renewed", string(readTestdata(t, "subkey-renewed.asc")), day(2026, 11, 1), nil, ""},
		{"signing subkey expired next to a valid key", string(readTestdata(t, "key.asc")) + subExpired, day(2025, 3, 1), []string{"a.asc: the signing subkey " + subFpr + " of the key " + subPrimaryFpr + " expired on 2025-01-31"}, ""},
		{"no signing key", string(readTestdata(t, "cert-only.asc")), day(2026, 11, 1), nil, "a.asc: the key BD44CA8AB9AC4BFA6B0396B1EFDEA27A4FE0448C has no key or subkey that can sign"},
		{"signing subkey revoked", string(readTestdata(t, "subkey-revoked.asc")), day(2026, 11, 1), nil, "a.asc: the key BD44CA8AB9AC4BFA6B0396B1EFDEA27A4FE0448C has no key or subkey that can sign"},
		{"RSA with 1024 bits", string(readTestdata(t, "rsa1024.asc")), day(2026, 11, 1), []string{"a.asc: the key 994EE216D45F86766171F0796821F1FA657A11A5 is RSA with 1024 bits; apt rejects RSA keys under 2048 bits"}, ""},
		{"DSA", string(readTestdata(t, "dsa.asc")), day(2026, 11, 1), []string{"a.asc: the key 3F75E778760C0255F4062371D274C72FC5BB6594 is DSA; apt rejects DSA keys"}, ""},
		{"SHA-1 self-signature", string(readTestdata(t, "sha1.asc")), day(2026, 11, 1), []string{"a.asc: the key 42EA6B67E06B03AB85A3ACC38DB5D5E055CE3E2A has a SHA-1 binding signature; apt rejects SHA-1 signatures"}, ""},
		{"SHA-1 subkey binding", string(readTestdata(t, "sha1-subkey.asc")), day(2026, 11, 1), []string{"a.asc: the signing subkey 3069B443F169A07443B243C2F914270C4B19B209 of the key B69A1C32A5F73DA759DC14FF17FB76E580AEFDD0 has a SHA-1 binding signature; apt rejects SHA-1 signatures"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r Repo
			got, err := r.SetKey("a.asc", []byte(tt.data), tt.now)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr || r.KeyData != nil {
					t.Fatalf("error = %v, key data set: %t; want %q", err, r.KeyData != nil, tt.wantErr)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tt.want) || string(r.KeyData) != tt.data {
				t.Fatalf("SetKey = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

// spec: Modules/repo
func TestRepoSigningSubkeys(t *testing.T) {
	packets := func(name string) []packet {
		var b64 strings.Builder
		for line := range strings.Lines(string(readTestdata(t, name))) {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "=") {
				b64.WriteString(line)
			}
		}
		raw, err := base64.StdEncoding.DecodeString(b64.String())
		if err != nil {
			t.Fatal(err)
		}
		p, err := readPackets(raw)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		name, file string
		edit       func([]packet) []packet
		wantErr    string
		wantWarn   string
	}{
		{"unbound subkey", "subkey-expired.asc", func(p []packet) []packet {
			return p[:len(p)-1]
		}, "has no key or subkey that can sign", ""},
		{"encryption subkey", "subkey-renewed.asc", func(p []packet) []packet {
			p[3].body[5] = 16
			return p
		}, "has no key or subkey that can sign", ""},
		{"SHA-1 embedded signature", "sha1-subkey.asc", func(p []packet) []packet {
			p[len(p)-1].body[3] = 10
			return p
		}, "", "has a SHA-1 binding signature"},
		{"expired then live subkey", "subkey-expired.asc", func(p []packet) []packet {
			extra := packets("subkey-renewed.asc")[3:]
			extra[0].body[len(extra[0].body)-1] ^= 1
			return append(p, extra...)
		}, "", ""},
		{"live then expired subkey", "subkey-renewed.asc", func(p []packet) []packet {
			extra := packets("subkey-expired.asc")[3:]
			extra[0].body[len(extra[0].body)-1] ^= 1
			return append(p, extra...)
		}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw []byte
			// These edits test packet metadata, not cryptographic signatures.
			for _, p := range tt.edit(packets(tt.file)) {
				raw = append(raw, 0xc0|p.tag, 255)
				raw = binary.BigEndian.AppendUint32(raw, uint32(len(p.body)))
				raw = append(raw, p.body...)
			}
			data := []byte(armorBegin + "\n\n" + base64.StdEncoding.EncodeToString(raw) + "\n" + armorEnd + "\n")
			var r Repo
			warnings, err := r.SetKey("a.asc", data, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("SetKey error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantWarn == "" && len(warnings) != 0 || tt.wantWarn != "" && (len(warnings) != 1 || !strings.Contains(warnings[0], tt.wantWarn)) {
				t.Errorf("warnings = %q, want %q", warnings, tt.wantWarn)
			}
		})
	}
}

// spec: Modules/repo
func TestLastSignerPrimaryExpiry(t *testing.T) {
	expiry := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	k := pgpKey{fingerprint: "primary", expires: expiry, subkeys: []pgpSubkey{{fingerprint: "sub"}}}
	signer, until, ok := lastSigner(k)
	if !ok || signer != "the key primary" || !until.Equal(expiry) {
		t.Errorf("lastSigner = %q, %v, %t; want primary expiry %v", signer, until, ok, expiry)
	}
}

// spec: Modules/repo
func TestKeyFileChanges(t *testing.T) {
	const p = "/etc/apt/keyrings/a.asc"
	key, rsa := readTestdata(t, "key.asc"), readTestdata(t, "rsa.asc")
	addTest := "add key " + testFpr + " winch test key <test@example.com>"
	addRSA := "add key " + rsaFpr + " winch rsa key <rsa@example.com>"
	tests := []struct {
		name     string
		old, new []byte
		want     []string
	}{
		{"no file", nil, readTestdata(t, "two-keys.asc"), []string{addTest, addRSA}},
		{"no file, two blocks", nil, readTestdata(t, "two-blocks.asc"), []string{addTest, addRSA}},
		{"renewed", readTestdata(t, "expiring.asc"), readTestdata(t, "renewed.asc"), []string{"update key " + expiringFpr + " (same key, new content)"}},
		{"added key", key, readTestdata(t, "two-blocks.asc"), []string{addRSA}},
		{"removed key", readTestdata(t, "two-blocks.asc"), key, []string{"remove key " + rsaFpr + " winch rsa key <rsa@example.com>"}},
		{"other key", key, rsa, []string{"remove key " + testFpr + " winch test key <test@example.com>", addRSA}},
		{"not a key", []byte("not a key\n"), key, []string{"replace " + p + ": is not an ASCII-armored OpenPGP public key", addTest}},
		{"same keys", []byte(strings.Replace(string(key), "\n\n", "\nComment: x\n\n", 1)), key, []string{"rewrite " + p}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keyFileChanges(p, tt.old, tt.new)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keyFileChanges = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestParsePGPKeyBad(t *testing.T) {
	lines := strings.Split(string(readTestdata(t, "key.asc")), "\n")
	tests := []struct {
		name, data, want string
	}{
		{"empty", "", "is not an ASCII-armored OpenPGP public key"},
		{"html", "<html>Not found</html>\n", "is not an ASCII-armored OpenPGP public key"},
		{"no end", strings.Join(lines[:4], "\n"), "has no end line"},
		{"bad base64", lines[0] + "\n\n!!!!\n" + "-----END PGP PUBLIC KEY BLOCK-----\n", "is not base64"},
		{"cut packet", lines[0] + "\n\n" + lines[2][:8] + "\n" + "-----END PGP PUBLIC KEY BLOCK-----\n", "ends inside a packet"},
		{"no packets", lines[0] + "\n\n-----END PGP PUBLIC KEY BLOCK-----\n", "holds no public key"},
		// A user ID packet first.
		{"no key packet", lines[0] + "\n\nzQF4\n-----END PGP PUBLIC KEY BLOCK-----\n", "holds no public key"},
		// A new-format key packet with a partial length.
		{"partial length", lines[0] + "\n\nxuA=\n-----END PGP PUBLIC KEY BLOCK-----\n", "a packet of partial length"},
		// A version 6 key packet.
		{"version 6", lines[0] + "\n\nxgEG\n-----END PGP PUBLIC KEY BLOCK-----\n", "the key has version 6; winch reads version 4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parsePGPKeys([]byte(tt.data)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

// Some key files have no empty line after the first line, or CRLF line ends.
func TestParsePGPKeyForms(t *testing.T) {
	key := readTestdata(t, "key.asc")
	for name, data := range map[string]string{
		"no empty line": strings.Replace(string(key), "\n\n", "\n", 1),
		"headers":       strings.Replace(string(key), "\n\n", "\nComment: winch\n\n", 1),
		"crlf":          strings.ReplaceAll(string(key), "\n", "\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parsePGPKeys([]byte(data))
			if err != nil || len(got) != 1 || got[0].fingerprint != testFpr {
				t.Fatalf("parsePGPKey = %+v, %v", got, err)
			}
		})
	}
}

// spec: Modules/repo
func TestSourceChanges(t *testing.T) {
	const p = "/etc/apt/sources.list.d/a.sources"
	want := "Types: deb\nURIs: https://x.example/apt\nSuites: trixie\nComponents: main\nSigned-By: /etc/apt/keyrings/a.asc\n"
	tests := []struct {
		name, old string
		want      []string
	}{
		{"suite", strings.Replace(want, "trixie", "bookworm", 1), []string{p + ": Suites bookworm → trixie"}},
		{"added key", strings.Replace(want, "Signed-By: /etc/apt/keyrings/a.asc\n", "", 1), []string{p + ": Signed-By (none) → /etc/apt/keyrings/a.asc"}},
		{"two fields", strings.Replace(strings.Replace(want, "trixie", "bookworm", 1), "main", "main contrib", 1), []string{p + ": Suites bookworm → trixie", p + ": Components main contrib → main"}},
		{"another field", strings.Replace(want, "trixie", "bookworm", 1) + "Enabled: no\n", []string{"rewrite " + p}},
		{"two stanzas", strings.Replace(want, "trixie", "bookworm", 1) + "\n" + want, []string{"rewrite " + p}},
		{"white space only", strings.Replace(want, "Types: deb", "Types:  deb", 1), []string{"rewrite " + p}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sourceChanges(p, []byte(tt.old), []byte(want)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sourceChanges = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSources(t *testing.T) {
	deb822 := `# Debian
Types: deb deb-src
URIs: https://a.example/debian/ https://b.example/debian
Suites: trixie trixie-updates
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 mDMEat+KcBYJKwYBBAHaRw8BAQdA
 -----END PGP PUBLIC KEY BLOCK-----

Types: deb
URIs: https://c.example/
# a comment in a stanza
Suites: stable
Components: main
Enabled: no

Types: deb
URIs: https://d.example/
Suites: stable
Enabled: yes

Types: deb
Suites: broken

Types: deb-src
URIs: https://e.example/
Suites: stable

URIs: https://f.example/
Suites: stable
`
	list := `deb [signed-by=/usr/share/keyrings/docker.gpg arch=amd64] https://download.docker.com/linux/debian trixie stable
# deb http://x.example/ y main
deb-src [ arch=amd64 ] http://deb.debian.org/debian trixie main

garbage
deb [arch=amd64 http://broken.example/ trixie main
`
	tests := []struct {
		name, file, data string
		want             []source
	}{
		{"deb822", "a.sources", deb822, []source{
			{uris: []string{"https://a.example/debian/", "https://b.example/debian"}, suites: []string{"trixie", "trixie-updates"}},
			{uris: []string{"https://d.example/"}, suites: []string{"stable"}},
		}},
		{"one-line", "a.list", list, []source{
			{uris: []string{"https://download.docker.com/linux/debian"}, suites: []string{"trixie"}},
		}},
		{"empty", "a.sources", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSources(tt.file, []byte(tt.data)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSources =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

// The image's /etc/apt/sources.list.d/debian.sources.
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
func TestRepoCheckOwnFile(t *testing.T) {
	r := &Repo{Name: "debian", URL: "http://deb.debian.org/debian", Suite: "trixie", Components: []string{"main"}}
	const p = "/etc/apt/sources.list.d/debian.sources"
	own := string(r.source())
	tests := []struct {
		name, old, want string
	}{
		{"the step's file", own, ""},
		{"an older suite", strings.Replace(own, "trixie", "bookworm", 1), ""},
		{"another URI", strings.Replace(own, "deb.debian.org", "ftp.debian.org", 1), ""},
		{"another URI and suite", strings.Replace(strings.Replace(own, "deb.debian.org", "ftp.debian.org", 1), "trixie", "bookworm", 1), ""},
		{"the URI with a final slash", strings.Replace(own, "debian\n", "debian/\n", 1), ""},
		{"one other source", "Types: deb\nURIs: mirror+file:///etc/apt/mirrors/debian-security.list\nSuites: trixie-security\n", ""},
		{"two URIs", strings.Replace(own, "URIs: http://deb.debian.org/debian", "URIs: http://deb.debian.org/debian http://ftp.debian.org/debian", 1), p + " holds deb http://ftp.debian.org/debian trixie, which is not this step's source; move it to another file"},
		{"two other entries", strings.Replace(own, "deb.debian.org", "ftp.debian.org", 1) + "\n" + strings.Replace(own, "deb.debian.org", "x.example", 1), p + " holds deb http://ftp.debian.org/debian trixie, which is not this step's source; move it to another file"},
		{"only a deb-src entry", strings.Replace(own, "Types: deb", "Types: deb-src", 1), p + " holds deb-src http://deb.debian.org/debian trixie, which is not this step's source; move it to another file"},
		{"the step's entry twice", own + "\n" + own, ""},
		{"empty", "", ""},
		{"the image's file", imageSources, p + " holds deb mirror+file:///etc/apt/mirrors/debian.list trixie, which is not this step's source; move it to another file"},
		{"another suite", strings.Replace(own, "Suites: trixie", "Suites: trixie trixie-updates", 1), p + " holds deb http://deb.debian.org/debian trixie-updates, which is not this step's source; move it to another file"},
		{"a deb-src entry", strings.Replace(own, "Types: deb", "Types: deb deb-src", 1), p + " holds deb-src http://deb.debian.org/debian trixie, which is not this step's source; move it to another file"},
		{"a disabled entry", own + "\nTypes: deb\nURIs: http://x.example/\nSuites: stable\nEnabled: no\n", p + " holds deb http://x.example/ stable, which is not this step's source; move it to another file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ""
			if err := r.checkOwnFile([]byte(tt.old)); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("checkOwnFile = %q, want %q", got, tt.want)
			}
		})
	}
	removed := *r
	removed.Removed = []string{"/etc/apt/sources.list.d"}
	if err := removed.checkOwnFile([]byte(imageSources)); err != nil {
		t.Errorf("checkOwnFile of a removed file = %v, want nil", err)
	}
}

func TestRepoRemoved(t *testing.T) {
	r := &Repo{Removed: []string{"/etc/apt/sources.list.d/a.list", "/etc/apt/b/"}}
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/apt/sources.list.d/a.list", true},
		{"/etc/apt/b/x.list", true},
		{"/etc/apt/sources.list.d/a.list2", false},
		{"/etc/apt/b2/x.list", false},
		{"/etc/apt/sources.list", false},
	}
	for _, tt := range tests {
		if got := r.removed(tt.path); got != tt.want {
			t.Errorf("removed(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestSourceHas(t *testing.T) {
	s := source{uris: []string{"https://a.example/debian/", "https://b.example/debian"}, suites: []string{"trixie", "trixie-updates"}}
	tests := []struct {
		uri, suite string
		want       bool
	}{
		{"https://a.example/debian/", "trixie", true},
		{"https://a.example/debian", "trixie", true},
		{"https://b.example/debian//", "trixie-updates", true},
		{"https://a.example/debian", "bookworm", false},
		{"http://a.example/debian", "trixie", false},
		{"https://a.example/", "trixie", false},
	}
	for _, tt := range tests {
		if got := s.has(tt.uri, tt.suite); got != tt.want {
			t.Errorf("has(%q, %q) = %v, want %v", tt.uri, tt.suite, got, tt.want)
		}
	}
}
