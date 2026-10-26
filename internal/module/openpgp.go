package module

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// pgpKey is an OpenPGP public key: the fingerprint of its primary key and
// its first user ID.
type pgpKey struct {
	fingerprint, userID string
}

const (
	armorBegin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	armorEnd   = "-----END PGP PUBLIC KEY BLOCK-----"
)

var errNotArmored = errors.New("is not an ASCII-armored OpenPGP public key")

// OpenPGP packet tags and signature types.
const (
	tagSignature  = 2
	tagPublicKey  = 6
	tagUserID     = 13
	sigRevocation = 0x20
)

// parsePGPKey reads an ASCII-armored public key block. It fails when the
// first key has a revocation signature.
func parsePGPKey(data []byte) (pgpKey, error) {
	text := strings.ReplaceAll(strings.TrimSpace(string(data)), "\r\n", "\n")
	body, ok := strings.CutPrefix(text, armorBegin+"\n")
	if !ok {
		return pgpKey{}, errNotArmored
	}
	body, _, ok = strings.Cut(body, armorEnd)
	if !ok {
		return pgpKey{}, errors.New("the key block has no end line")
	}
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
		return pgpKey{}, errors.New("the key data is not base64")
	}
	packets, err := readPackets(raw)
	if err != nil {
		return pgpKey{}, err
	}
	if len(packets) == 0 || packets[0].tag != tagPublicKey || len(packets[0].body) == 0 {
		return pgpKey{}, errors.New("the key block holds no public key")
	}
	key := packets[0].body
	if key[0] != 4 {
		return pgpKey{}, fmt.Errorf("the key has version %d; winch reads version 4", key[0])
	}
	h := sha1.New()
	h.Write([]byte{0x99})
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(key))))
	h.Write(key)
	k := pgpKey{fingerprint: strings.ToUpper(hex.EncodeToString(h.Sum(nil)))}
	for _, p := range packets[1:] {
		if p.tag == tagPublicKey {
			break
		}
		if p.tag == tagUserID && k.userID == "" {
			k.userID = string(p.body)
		}
		// A key revocation comes before the user IDs and binds to the
		// primary key.
		if p.tag == tagSignature && k.userID == "" && sigType(p.body) == sigRevocation {
			return pgpKey{}, fmt.Errorf("the key %s is revoked", k.fingerprint)
		}
	}
	return k, nil
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
	tag  byte
	body []byte
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
		out = append(out, packet{tag: tag, body: b[hl : hl+n]})
		b = b[hl+n:]
	}
	return out, nil
}
