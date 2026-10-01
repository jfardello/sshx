package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

type agentImportedKey struct {
	key       registeredAgentKey
	signer    ssh.Signer
	destroy   func()
	lifetime  time.Duration
	expires   time.Time
	timer     *time.Timer
	signMutex sync.Mutex
	users     int
	retired   bool
}

func clearAgentInteger(n *big.Int) {
	if n != nil {
		clear(n.Bits())
		n.SetInt64(0)
	}
}
func parseAgentAdd(body []byte) (imported *agentImportedKey, err error) {
	if len(body) < 2 || len(body) > maxAgentFrameBytes || (body[0] != 17 && body[0] != 25) {
		return nil, errAgentDenied
	}
	constrained := body[0] == 25
	data := body[1:]
	read := func(max int) ([]byte, bool) {
		value, rest, ok := agentWireString(data)
		if !ok || len(value) > max {
			return nil, false
		}
		data = rest
		return value, true
	}
	kind, ok := read(64)
	if !ok {
		return nil, errAgentDenied
	}
	var private any
	cleanup := func() {}
	defer func() {
		if err != nil {
			cleanup()
		}
	}()
	switch string(kind) {
	case ssh.KeyAlgoED25519:
		public, ok := read(32)
		if !ok || len(public) != 32 {
			return nil, errAgentDenied
		}
		raw, ok := read(64)
		if !ok || len(raw) != 64 {
			return nil, errAgentDenied
		}
		key := append(ed25519.PrivateKey(nil), raw...)
		cleanup = func() { clearBytes(key) }
		seed := key.Seed()
		derived := ed25519.NewKeyFromSeed(seed)
		clearBytes(seed)
		defer clearBytes(derived)
		if !bytes.Equal(key, derived) || !bytes.Equal(public, key[32:]) {
			return nil, errAgentDenied
		}
		private = key
	case ssh.KeyAlgoRSA:
		values := make([]*big.Int, 6)
		cleanup = func() {
			for _, value := range values {
				clearAgentInteger(value)
			}
		}
		for i, max := range []int{1025, 5, 1025, 513, 513, 513} {
			raw, ok := read(max)
			if !ok {
				return nil, errAgentDenied
			}
			n, ok := agentPositiveMPInt(raw)
			if !ok {
				return nil, errAgentDenied
			}
			values[i] = n
		}
		n, e, d, iqmp, p, q := values[0], values[1], values[2], values[3], values[4], values[5]
		if n.BitLen() < 2048 || n.BitLen() > 8192 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, errAgentDenied
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())}, D: d, Primes: []*big.Int{p, q}}
		if key.Validate() != nil {
			return nil, errAgentDenied
		}
		key.Precompute()
		old := cleanup
		cleanup = func() {
			old()
			clearAgentInteger(key.Precomputed.Dp)
			clearAgentInteger(key.Precomputed.Dq)
			clearAgentInteger(key.Precomputed.Qinv)
		}
		if key.Precomputed.Qinv.Cmp(iqmp) != 0 {
			return nil, errAgentDenied
		}
		private = key
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		curveName, ok := read(16)
		if !ok {
			return nil, errAgentDenied
		}
		var curve elliptic.Curve
		switch string(kind) {
		case ssh.KeyAlgoECDSA256:
			curve = elliptic.P256()
		case ssh.KeyAlgoECDSA384:
			curve = elliptic.P384()
		case ssh.KeyAlgoECDSA521:
			curve = elliptic.P521()
		}
		if string(kind) != "ecdsa-sha2-"+string(curveName) {
			return nil, errAgentDenied
		}
		point, ok := read(133)
		if !ok {
			return nil, errAgentDenied
		}
		raw, ok := read(67)
		if !ok {
			return nil, errAgentDenied
		}
		d, ok := agentPositiveMPInt(raw)
		if !ok {
			return nil, errAgentDenied
		}
		cleanup = func() { clearAgentInteger(d) }
		if d.Cmp(curve.Params().N) >= 0 {
			return nil, errAgentDenied
		}
		x, y := elliptic.Unmarshal(curve, point)
		if x == nil {
			return nil, errAgentDenied
		}
		scalar := d.Bytes()
		dx, dy := curve.ScalarBaseMult(scalar)
		clearBytes(scalar)
		if x.Cmp(dx) != 0 || y.Cmp(dy) != 0 {
			return nil, errAgentDenied
		}
		private = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
	default:
		return nil, errAgentDenied
	}
	comment, ok := read(128)
	if !ok || strings.IndexFunc(string(comment), unicode.IsControl) >= 0 {
		return nil, errAgentDenied
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, errAgentDenied
	}
	result := &agentImportedKey{signer: signer, destroy: cleanup, key: registeredAgentKey{publicKey: signer.PublicKey(), record: agentKeyRecord{ID: "volatile", Enabled: true, Policy: "unrestricted-local", Comment: string(comment)}}}
	if !constrained && len(data) != 0 {
		return nil, errAgentDenied
	}
	seen := map[byte]bool{}
	for len(data) > 0 {
		tag := data[0]
		data = data[1:]
		if seen[tag] {
			return nil, errAgentDenied
		}
		seen[tag] = true
		switch tag {
		case 1:
			if len(data) < 4 {
				return nil, errAgentDenied
			}
			seconds := binary.BigEndian.Uint32(data)
			data = data[4:]
			if seconds == 0 {
				return nil, errAgentDenied
			}
			result.lifetime = time.Duration(seconds) * time.Second
		case 2:
			result.key.record.Confirm = true
		case 255:
			name, ok := read(256)
			if !ok {
				return nil, errAgentDenied
			}
			details, ok := read(maxAgentConstraintBytes)
			if !ok {
				return nil, errAgentDenied
			}
			wire := append([]byte{255}, ssh.Marshal(struct{ Name, Details []byte }{name, details})...)
			policy, err := parseAgentDestinationConstraint(wire)
			if err != nil {
				return nil, errAgentDenied
			}
			compiled, err := compileAgentPolicy(policy)
			if err != nil {
				return nil, errAgentDenied
			}
			result.key.policy = compiled
			result.key.record.Policy = "destination-constrained"
			result.key.record.Destinations = policy
		default:
			return nil, errAgentDenied // Includes ambiguous legacy tag 3/max-sign.
		}
	}
	return result, nil
}
func agentPositiveMPInt(raw []byte) (*big.Int, bool) {
	if len(raw) == 0 || raw[0]&128 != 0 || (len(raw) > 1 && raw[0] == 0 && raw[1]&128 == 0) {
		return nil, false
	}
	n := new(big.Int).SetBytes(raw)
	return n, n.Sign() > 0
}
