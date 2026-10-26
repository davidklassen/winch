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
	// data is the packets of the key; a renewed key has new data.
	data string
}

const (
	armorBegin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	armorEnd   = "-----END PGP PUBLIC KEY BLOCK-----"
)

var errNotArmored = errors.New("is not an ASCII-armored OpenPGP public key")

// OpenPGP packet tags, signature types, and signature subpacket types.
const (
	tagSignature = 2
	tagPublicKey = 6
	tagUserID    = 13

	sigCertGeneric  = 0x10
	sigCertPositive = 0x13
	sigDirect       = 0x1f
	sigRevocation   = 0x20

	subCreated   = 2
	subExpires   = 9
	subIssuer    = 16
	subIssuerFpr = 33
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
// self-signature of the primary key sets when it expires.
func parsePGPKey(packets []packet) (pgpKey, error) {
	key := packets[0].body
	if len(key) == 0 {
		return pgpKey{}, errors.New("the key block holds no public key")
	}
	if key[0] != 4 {
		return pgpKey{}, fmt.Errorf("the key has version %d; winch reads version 4", key[0])
	}
	if len(key) < 5 {
		return pgpKey{}, errors.New("the key data ends inside a packet")
	}
	h := sha1.New()
	h.Write([]byte{0x99})
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(key))))
	h.Write(key)
	fpr := h.Sum(nil)
	k := pgpKey{fingerprint: strings.ToUpper(hex.EncodeToString(fpr))}
	created := time.Unix(int64(binary.BigEndian.Uint32(key[1:5])), 0).UTC()
	var newest time.Time
	var data strings.Builder
	for i, p := range packets {
		data.Write(p.raw)
		if i == 0 {
			continue
		}
		if p.tag == tagUserID && k.userID == "" {
			k.userID = string(p.body)
		}
		if p.tag != tagSignature {
			continue
		}
		t := sigType(p.body)
		// A key revocation comes before the user IDs and binds to the
		// primary key.
		if k.userID == "" && t == sigRevocation {
			return pgpKey{}, fmt.Errorf("the key %s is revoked", k.fingerprint)
		}
		if t != sigDirect && (t < sigCertGeneric || t > sigCertPositive) {
			continue
		}
		s, ok := parseSelfSig(p.body, fpr)
		if !ok || s.created.Before(newest) {
			continue
		}
		newest, k.expires = s.created, time.Time{}
		if s.expires > 0 {
			k.expires = created.Add(time.Duration(s.expires) * time.Second)
		}
	}
	k.data = data.String()
	return k, nil
}

type selfSig struct {
	created time.Time
	// expires is the key lifetime in seconds, or 0.
	expires uint32
}

// parseSelfSig reads a version 4 signature that the key with fingerprint fpr
// issued. Only the hashed area sets the creation and expiration times.
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
	var s selfSig
	self := false
	for i, area := range [][]byte{body[6 : 6+n], body[8+n : 8+n+m]} {
		for typ, v := range subpackets(area) {
			switch {
			case typ == subIssuer && len(v) == 8:
				self = self || string(v) == string(fpr[12:])
			case typ == subIssuerFpr && len(v) == 21 && v[0] == 4:
				self = self || string(v[1:]) == string(fpr)
			case i == 0 && typ == subCreated && len(v) == 4:
				s.created = time.Unix(int64(binary.BigEndian.Uint32(v)), 0).UTC()
			case i == 0 && typ == subExpires && len(v) == 4:
				s.expires = binary.BigEndian.Uint32(v)
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
