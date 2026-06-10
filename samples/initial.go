package samples

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

var (
	chromeInitialOnce  sync.Once
	chromeInitialBytes []byte
)

func ChromeInitial() []byte {
	chromeInitialOnce.Do(func() {
		chromeInitialBytes = buildMinimalQuICInitial([8]byte{}, "cloudflare.com")
	})
	return chromeInitialBytes
}

func IsVersionNegotiation(pkt []byte) bool {
	if len(pkt) < 5 {
		return false
	}
	if pkt[0]&0x80 == 0 {
		return false
	}
	return binary.BigEndian.Uint32(pkt[1:5]) == 0x00000000
}

var initialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

func hkdfExtract(ikm, salt []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var prev []byte
	for i := 1; len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{byte(i)})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

func hkdfExpandLabel(prk []byte, label string, context []byte, length int) []byte {
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len(fullLabel)))
	hkdfLabel = append(hkdfLabel, []byte(fullLabel)...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)
	return hkdfExpand(prk, hkdfLabel, length)
}

func buildMinimalQuICInitial(dcid [8]byte, sni string) []byte {
	clientHello := buildClientHello(sni)

	cryptoFrame := buildCryptoFrame(clientHello)

	const minPlaintext = 1162
	plaintext := cryptoFrame
	if len(plaintext) < minPlaintext {
		padding := make([]byte, minPlaintext-len(plaintext))
		plaintext = append(plaintext, padding...)
	}

	initialSecret := hkdfExtract(dcid[:], initialSalt)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	key := hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	iv := hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	hp := hkdfExpandLabel(clientSecret, "quic hp", nil, 16)

	scid := make([]byte, 8)
	rand.Read(scid)

	payloadLen := len(plaintext) + 16 + 4
	header := buildLongHeader(dcid[:], scid, payloadLen)

	nonce := make([]byte, 12)
	copy(nonce, iv)

	aad := header

	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	if len(ciphertext) < 20 {
		return nil
	}
	sample := ciphertext[4:20]

	hpBlock, _ := aes.NewCipher(hp)
	mask := make([]byte, aes.BlockSize)
	hpBlock.Encrypt(mask, sample)

	protected := make([]byte, len(header)+len(ciphertext))
	copy(protected, header)
	copy(protected[len(header):], ciphertext)

	pnOffset := len(header) - 4

	protected[0] ^= mask[0] & 0x0f
	protected[pnOffset+0] ^= mask[1]
	protected[pnOffset+1] ^= mask[2]
	protected[pnOffset+2] ^= mask[3]
	protected[pnOffset+3] ^= mask[4]

	return protected
}

func buildLongHeader(dcid, scid []byte, payloadLen int) []byte {
	var h []byte
	h = append(h, 0xC3)
	h = append(h, 0x00, 0x00, 0x00, 0x01)
	h = append(h, byte(len(dcid)))
	h = append(h, dcid...)
	h = append(h, byte(len(scid)))
	h = append(h, scid...)
	h = append(h, 0x00)
	h = append(h, byte(0x40|(payloadLen>>8)), byte(payloadLen))
	h = append(h, 0x00, 0x00, 0x00, 0x00)
	return h
}

func buildCryptoFrame(data []byte) []byte {
	var f []byte
	f = append(f, 0x06)
	f = append(f, 0x00)
	l := len(data)
	if l < 64 {
		f = append(f, byte(l))
	} else {
		f = append(f, byte(0x40|(l>>8)), byte(l))
	}
	f = append(f, data...)
	return f
}

func buildClientHello(sni string) []byte {
	privKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pubKeyBytes := privKey.PublicKey().Bytes()

	random := make([]byte, 32)
	rand.Read(random)

	exts := buildExtensions(sni, pubKeyBytes)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, random...)
	body = append(body, 0x00)                   // legacy_session_id length = 0
	body = append(body, 0x00, 0x04)             // cipher_suites length = 4
	body = append(body, 0x13, 0x01)             // TLS_AES_128_GCM_SHA256
	body = append(body, 0x13, 0x02)             // TLS_AES_256_GCM_SHA384
	body = append(body, 0x01, 0x00)             // compression_methods: length=1, null
	body = append(body, uint16be(len(exts))...) // extensions length
	body = append(body, exts...)

	var hs []byte
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs, uint24be(len(body))...)
	hs = append(hs, body...)
	return hs
}

func buildExtensions(sni string, x25519PubKey []byte) []byte {
	var exts []byte

	exts = append(exts, buildServerNameExt(sni)...)

	svData := []byte{0x02, 0x03, 0x04}
	exts = append(exts, buildExt(0x002b, svData)...)

	sgData := []byte{0x00, 0x02, 0x00, 0x1d} // list length=2, x25519=0x001d
	exts = append(exts, buildExt(0x000a, sgData)...)

	var ksEntry []byte
	ksEntry = append(ksEntry, 0x00, 0x1d)               // group: x25519
	ksEntry = append(ksEntry, uint16be(len(x25519PubKey))...)
	ksEntry = append(ksEntry, x25519PubKey...)
	ksData := append(uint16be(len(ksEntry)), ksEntry...)
	exts = append(exts, buildExt(0x0033, ksData)...)

	alpnProto := append([]byte{byte(len("h3"))}, []byte("h3")...)
	alpnData := append(uint16be(len(alpnProto)), alpnProto...)
	exts = append(exts, buildExt(0x0010, alpnData)...)

	exts = append(exts, buildExt(0x0039, []byte{})...)

	return exts
}

func buildServerNameExt(sni string) []byte {
	nameBytes := []byte(sni)
	var entry []byte
	entry = append(entry, 0x00)                        // name type: host_name
	entry = append(entry, uint16be(len(nameBytes))...) // name length
	entry = append(entry, nameBytes...)

	list := append(uint16be(len(entry)), entry...)

	return buildExt(0x0000, list)
}

func buildExt(extType uint16, data []byte) []byte {
	var e []byte
	e = append(e, uint16be(int(extType))...)
	e = append(e, uint16be(len(data))...)
	e = append(e, data...)
	return e
}

func uint16be(v int) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

func uint24be(v int) []byte {
	return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
}
