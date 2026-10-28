package module

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
	"time"
)

// pgpKey is an OpenPGP public key: the fingerprint of its primary key and
// its first user ID.
type pgpKey struct {
	fingerprint, userID string
	// expires is when the primary key expires, or zero.
	expires time.Time
	// signs reports whether the primary key can sign.
	signs bool
	// weak says why apt rejects the primary key, or is empty.
	weak string
	// subkeys are the signing subkeys that are not revoked.
	subkeys []pgpSubkey
	// data is the packets of the key; a renewed key has new data.
	data string
}

type pgpSubkey struct {
	fingerprint string
	expires     time.Time
	weak        string
}

const (
	armorBegin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	armorEnd   = "-----END PGP PUBLIC KEY BLOCK-----"
)

var errNotArmored = errors.New("is not an ASCII-armored OpenPGP public key")

const sha1Binding = "has a SHA-1 binding signature; apt rejects SHA-1 signatures"

// OpenPGP packet tags, signature types, and signature subpacket types.
const (
	tagSignature = 2
	tagPublicKey = 6
	tagUserID    = 13
	tagSubkey    = 14

	sigCertGeneric  = 0x10
	sigCertPositive = 0x13
	sigSubkey       = 0x18
	sigDirect       = 0x1f
	sigRevocation   = 0x20
	sigSubkeyRevoke = 0x28

	subCreated   = 2
	subExpires   = 9
	subIssuer    = 16
	subKeyFlags  = 27
	subEmbedded  = 32
	subIssuerFpr = 33

	flagSign = 0x02
	hashSHA1 = 2
)

// parsePGPKeys reads the keys of one or more ASCII-armored public key blocks.
// It fails when a key has a revocation signature.
func parsePGPKeys(data []byte) ([]pgpKey, error) {
	text := strings.ReplaceAll(strings.TrimSpace(string(data)), "\r\n", "\n")
	if !strings.HasPrefix(text, armorBegin+"\n") {
		return nil, errNotArmored
	}
	var keys []pgpKey
	for {
		_, body, ok := strings.Cut(text, armorBegin+"\n")
		if !ok {
			return keys, nil
		}
		body, text, ok = strings.Cut(body, armorEnd)
		if !ok {
			return nil, errors.New("the key block has no end line")
		}
		k, err := parseBlock(body)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k...)
	}
}

func parseBlock(body string) ([]pgpKey, error) {
	// The armor headers, "Key: value" lines, end at the first empty line;
	// some files have neither. The line that starts with "=" is the checksum.
	var b64 strings.Builder
	headers := true
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if headers && (line == "" || strings.Contains(line, ": ")) {
			headers = line != ""
			continue
		}
		headers = false
		if !strings.HasPrefix(line, "=") {
			b64.WriteString(line)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, errors.New("the key data is not base64")
	}
	packets, err := readPackets(raw)
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 || packets[0].tag != tagPublicKey {
		return nil, errors.New("the key block holds no public key")
	}
	var keys []pgpKey
	for len(packets) > 0 {
		n := 1 + slices.IndexFunc(packets[1:], func(p packet) bool { return p.tag == tagPublicKey })
		if n == 0 {
			n = len(packets)
		}
		k, err := parsePGPKey(packets[:n])
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
		packets = packets[n:]
	}
	return keys, nil
}

// parsePGPKey reads a key from its packets, the primary key first. The newest
// self-signature of the primary key sets when it expires and whether it signs;
// the newest binding signature of a subkey does the same for the subkey.
func parsePGPKey(packets []packet) (pgpKey, error) {
	key := packets[0].body
	if len(key) == 0 {
		return pgpKey{}, errors.New("the key block holds no public key")
	}
	if key[0] != 4 {
		return pgpKey{}, fmt.Errorf("the key has version %d; winch reads version 4", key[0])
	}
	if len(key) < 6 {
		return pgpKey{}, errors.New("the key data ends inside a packet")
	}
	fpr := pgpFingerprint(key)
	k := pgpKey{fingerprint: strings.ToUpper(hex.EncodeToString(fpr)), weak: weakAlgorithm(key)}
	// sub is the subkey that the packets now belong to.
	var sub []byte
	var subSig selfSig
	bound, revoked := false, false
	endSubkey := func() {
		if len(sub) < 6 || sub[0] != 4 || !bound || revoked || !subSig.signs(sub[5]) {
			return
		}
		s := pgpSubkey{fingerprint: strings.ToUpper(hex.EncodeToString(pgpFingerprint(sub))), weak: weakAlgorithm(sub)}
		if subSig.expires > 0 {
			s.expires = keyCreated(sub).Add(time.Duration(subSig.expires) * time.Second)
		}
		if s.weak == "" && (subSig.hash == hashSHA1 || subSig.backHash == hashSHA1) {
			s.weak = sha1Binding
		}
		k.subkeys = append(k.subkeys, s)
	}
	var primary selfSig
	var data strings.Builder
	for i, p := range packets {
		data.Write(p.raw)
		if i == 0 {
			continue
		}
		switch p.tag {
		case tagUserID:
			if k.userID == "" && sub == nil {
				k.userID = string(p.body)
			}
			continue
		case tagSubkey:
			endSubkey()
			sub, subSig, bound, revoked = p.body, selfSig{}, false, false
			continue
		}
		if p.tag != tagSignature {
			continue
		}
		t := sigType(p.body)
		// A key revocation comes before the user IDs and binds to the
		// primary key.
		if k.userID == "" && sub == nil && t == sigRevocation {
			return pgpKey{}, fmt.Errorf("the key %s is revoked", k.fingerprint)
		}
		s, ok := parseSelfSig(p.body, fpr)
		if !ok {
			continue
		}
		switch {
		case sub != nil && t == sigSubkeyRevoke:
			revoked = true
		case sub != nil && t == sigSubkey && !s.created.Before(subSig.created):
			subSig, bound = s, true
		case sub == nil && (t == sigDirect || t >= sigCertGeneric && t <= sigCertPositive) && !s.created.Before(primary.created):
			primary = s
		}
	}
	endSubkey()
	k.signs = primary.signs(key[5])
	if primary.expires > 0 {
		k.expires = keyCreated(key).Add(time.Duration(primary.expires) * time.Second)
	}
	if k.weak == "" && primary.hash == hashSHA1 {
		k.weak = sha1Binding
	}
	k.data = data.String()
	return k, nil
}

// pgpFingerprint returns the fingerprint of a version 4 key packet body.
func pgpFingerprint(key []byte) []byte {
	h := sha1.New()
	h.Write([]byte{0x99})
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(key))))
	h.Write(key)
	return h.Sum(nil)
}

func keyCreated(key []byte) time.Time {
	return time.Unix(int64(binary.BigEndian.Uint32(key[1:5])), 0).UTC()
}

// weakAlgorithm says why apt rejects the algorithm of a version 4 key
// packet body, or returns "".
func weakAlgorithm(key []byte) string {
	switch key[5] {
	case 17:
		return "is DSA; apt rejects DSA keys"
	case 1, 2, 3:
		if len(key) < 8 {
			return ""
		}
		if bits := binary.BigEndian.Uint16(key[6:8]); bits < 2048 {
			return fmt.Sprintf("is RSA with %d bits; apt rejects RSA keys under 2048 bits", bits)
		}
	}
	return ""
}

type selfSig struct {
	created time.Time
	// expires is the key lifetime in seconds, or 0.
	expires uint32
	// flags is the key flags subpacket, or nil.
	flags []byte
	// hash is the hash algorithm; backHash is the one of the embedded
	// signature, or 0.
	hash, backHash byte
}

// Without key flags, the algorithm decides whether the key can sign.
func (s selfSig) signs(algorithm byte) bool {
	switch algorithm {
	case 1, 3, 17, 19, 22, 27, 28: // RSA, DSA, ECDSA, EdDSA.
		return s.flags == nil || len(s.flags) > 0 && s.flags[0]&flagSign != 0
	default:
		return false
	}
}

// parseSelfSig reads a version 4 signature that the key with fingerprint fpr
// issued. Only the hashed area sets the creation and expiration times and the
// key flags.
func parseSelfSig(body, fpr []byte) (selfSig, bool) {
	if len(body) < 6 || body[0] != 4 {
		return selfSig{}, false
	}
	n := int(binary.BigEndian.Uint16(body[4:6]))
	if len(body) < 8+n {
		return selfSig{}, false
	}
	m := int(binary.BigEndian.Uint16(body[6+n : 8+n]))
	if len(body) < 8+n+m {
		return selfSig{}, false
	}
	s := selfSig{hash: body[3]}
	self := false
	for i, area := range [][]byte{body[6 : 6+n], body[8+n : 8+n+m]} {
		for typ, v := range subpackets(area) {
			switch {
			case typ == subIssuer && len(v) == 8:
				self = self || string(v) == string(fpr[12:])
			case typ == subIssuerFpr && len(v) == 21 && v[0] == 4:
				self = self || string(v[1:]) == string(fpr)
			case typ == subEmbedded && len(v) > 3 && v[0] == 4:
				s.backHash = v[3]
			case i == 0 && typ == subCreated && len(v) == 4:
				s.created = time.Unix(int64(binary.BigEndian.Uint32(v)), 0).UTC()
			case i == 0 && typ == subExpires && len(v) == 4:
				s.expires = binary.BigEndian.Uint32(v)
			case i == 0 && typ == subKeyFlags:
				s.flags = v
			}
		}
	}
	return s, self
}

// subpackets yields the type, without the critical bit, and the data of each
// signature subpacket in area. It stops at a malformed subpacket.
func subpackets(area []byte) iter.Seq2[byte, []byte] {
	return func(yield func(byte, []byte) bool) {
		for len(area) > 0 {
			var n, hl int
			switch o := int(area[0]); {
			case o < 192:
				n, hl = o, 1
			case o < 255 && len(area) > 1:
				n, hl = (o-192)<<8+int(area[1])+192, 2
			case o == 255 && len(area) > 4:
				n, hl = int(binary.BigEndian.Uint32(area[1:5])), 5
			default:
				return
			}
			if n == 0 || len(area)-hl < n {
				return
			}
			if !yield(area[hl]&0x7f, area[hl+1:hl+n]) {
				return
			}
			area = area[hl+n:]
		}
	}
}

// sigType returns the type of a signature packet, or 0.
func sigType(body []byte) byte {
	switch {
	case len(body) > 2 && body[0] == 3:
		return body[2]
	case len(body) > 1:
		return body[1]
	}
	return 0
}

type packet struct {
	tag byte
	// raw is the packet with its header.
	raw, body []byte
}

// readPackets splits OpenPGP data into packets, in the old and the new
// header format.
func readPackets(b []byte) ([]packet, error) {
	var out []packet
	short := errors.New("the key data ends inside a packet")
	for len(b) > 0 {
		h := b[0]
		if h&0x80 == 0 {
			return nil, errors.New("the key data is not OpenPGP")
		}
		var tag byte
		var n, hl int
		if h&0x40 != 0 {
			tag = h & 0x3f
			if len(b) < 2 {
				return nil, short
			}
			switch o := int(b[1]); {
			case o < 192:
				n, hl = o, 2
			case o < 224:
				if len(b) < 3 {
					return nil, short
				}
				n, hl = (o-192)<<8+int(b[2])+192, 3
			case o == 255:
				if len(b) < 6 {
					return nil, short
				}
				n, hl = int(binary.BigEndian.Uint32(b[2:6])), 6
			default:
				return nil, errors.New("the key data has a packet of partial length")
			}
		} else {
			tag = h >> 2 & 0x0f
			if h&3 == 3 {
				return nil, errors.New("the key data has a packet of no length")
			}
			hl = 1 + 1<<(h&3)
			if len(b) < hl {
				return nil, short
			}
			for _, c := range b[1:hl] {
				n = n<<8 | int(c)
			}
		}
		if len(b)-hl < n {
			return nil, short
		}
		out = append(out, packet{tag: tag, raw: b[:hl+n], body: b[hl : hl+n]})
		b = b[hl+n:]
	}
	return out, nil
}
