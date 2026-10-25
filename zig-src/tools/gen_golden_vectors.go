// VMess AEAD / VLESS 黄金测试向量生成器
// 依据: D:\workspace\Xray-core-zig @ 1b1647cd (v26.10.21)
// KDF/CreateAuthID/SealVMessAEADHeader/EncodeResponseHeader 逻辑逐字取自上游:
//   proxy/vmess/aead/kdf.go, consts.go, authid.go, encrypt.go
//   proxy/vmess/encoding/client.go (EncodeRequestHeader), server.go (EncodeResponseHeader)
//   common/protocol/id.go (cmdKey)
// 唯一改动: 将 time.Now()/crypto/rand 固化为可复现定值。
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"os"
)

// ==== VERBATIM: proxy/vmess/aead/kdf.go ====

type hash2 struct {
	hash.Hash
}

func KDF(key []byte, path ...string) []byte {
	hmacf := hmac.New(sha256.New, []byte(KDFSaltConstVMessAEADKDF))

	for _, v := range path {
		first := true
		hmacf = hmac.New(func() hash.Hash {
			if first {
				first = false
				return hash2{hmacf}
			}
			return hmacf
		}, []byte(v))
	}
	hmacf.Write(key)
	return hmacf.Sum(nil)
}

func KDF16(key []byte, path ...string) []byte {
	r := KDF(key, path...)
	return r[:16]
}

// ==== VERBATIM: proxy/vmess/aead/consts.go ====

const (
	KDFSaltConstAuthIDEncryptionKey             = "AES Auth ID Encryption"
	KDFSaltConstAEADRespHeaderLenKey            = "AEAD Resp Header Len Key"
	KDFSaltConstAEADRespHeaderLenIV             = "AEAD Resp Header Len IV"
	KDFSaltConstAEADRespHeaderPayloadKey        = "AEAD Resp Header Key"
	KDFSaltConstAEADRespHeaderPayloadIV         = "AEAD Resp Header IV"
	KDFSaltConstVMessAEADKDF                    = "VMess AEAD KDF"
	KDFSaltConstVMessHeaderPayloadAEADKey       = "VMess Header AEAD Key"
	KDFSaltConstVMessHeaderPayloadAEADIV        = "VMess Header AEAD Nonce"
	KDFSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length"
	KDFSaltConstVMessHeaderPayloadLengthAEADIV  = "VMess Header AEAD Nonce_Length"
)

// ==== CreateAuthID (authid.go)，随机 4 字节固化为入参 ====

func CreateAuthIDFixed(cmdKey []byte, t int64, rnd [4]byte) [16]byte {
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.BigEndian, t)
	buf.Write(rnd[:])
	zero := crc32.ChecksumIEEE(buf.Bytes())
	binary.Write(buf, binary.BigEndian, zero)
	block, err := aes.NewCipher(KDF16(cmdKey, KDFSaltConstAuthIDEncryptionKey))
	if err != nil {
		panic(err)
	}
	var result [16]byte
	block.Encrypt(result[:], buf.Bytes())
	return result
}

// ==== SealVMessAEADHeader (encrypt.go)，时间/nonce 固化为入参 ====

func SealHeaderFixed(key [16]byte, data []byte, t int64, rnd [4]byte, connectionNonce []byte) []byte {
	generatedAuthID := CreateAuthIDFixed(key[:], t, rnd)

	var payloadHeaderLengthAEADEncrypted []byte
	{
		k := KDF16(key[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, string(generatedAuthID[:]), string(connectionNonce))
		n := KDF(key[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, string(generatedAuthID[:]), string(connectionNonce))[:12]
		block, _ := aes.NewCipher(k)
		g, _ := cipher.NewGCM(block)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(data)))
		payloadHeaderLengthAEADEncrypted = g.Seal(nil, n, l[:], generatedAuthID[:])
	}

	var payloadHeaderAEADEncrypted []byte
	{
		k := KDF16(key[:], KDFSaltConstVMessHeaderPayloadAEADKey, string(generatedAuthID[:]), string(connectionNonce))
		n := KDF(key[:], KDFSaltConstVMessHeaderPayloadAEADIV, string(generatedAuthID[:]), string(connectionNonce))[:12]
		block, _ := aes.NewCipher(k)
		g, _ := cipher.NewGCM(block)
		payloadHeaderAEADEncrypted = g.Seal(nil, n, data, generatedAuthID[:])
	}

	var out bytes.Buffer
	out.Write(generatedAuthID[:])
	out.Write(payloadHeaderLengthAEADEncrypted)
	out.Write(connectionNonce)
	out.Write(payloadHeaderAEADEncrypted)
	return out.Bytes()
}

// ==== OpenVMessAEADHeader (encrypt.go)，reader 换成字节切片，用于自校验 ====

func OpenHeaderFixed(key [16]byte, authid [16]byte, data []byte) ([]byte, error) {
	if len(data) < 26 {
		return nil, fmt.Errorf("short")
	}
	encLen := data[:18]
	nonce := data[18:26]

	var length uint16
	{
		k := KDF16(key[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, string(authid[:]), string(nonce))
		n := KDF(key[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, string(authid[:]), string(nonce))[:12]
		block, _ := aes.NewCipher(k)
		g, _ := cipher.NewGCM(block)
		pt, err := g.Open(nil, n, encLen, authid[:])
		if err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint16(pt)
	}

	encPay := data[26:]
	if len(encPay) != int(length)+16 {
		return nil, fmt.Errorf("length mismatch")
	}
	{
		k := KDF16(key[:], KDFSaltConstVMessHeaderPayloadAEADKey, string(authid[:]), string(nonce))
		n := KDF(key[:], KDFSaltConstVMessHeaderPayloadAEADIV, string(authid[:]), string(nonce))[:12]
		block, _ := aes.NewCipher(k)
		g, _ := cipher.NewGCM(block)
		return g.Open(nil, n, encPay, authid[:])
	}
}

// ==== EncodeResponseHeader (encoding/server.go:313-354)，TCP 场景 command=nil ====

func ResponseHeaderFixed(requestBodyKey, requestBodyIV [16]byte, responseHeaderByte, option byte) []byte {
	bodyKeySum := sha256.Sum256(requestBodyKey[:])
	bodyIVSum := sha256.Sum256(requestBodyIV[:])
	responseBodyKey := bodyKeySum[:16]
	responseBodyIV := bodyIVSum[:16]

	// 内层明文：server.go:313-330 把 encryptionWriter 重新指向普通 bytes.Buffer，
	// CFB 的 aesStream 只赋给 s.responseWriter（响应体）——头部内层不加密。
	// （M8 Go 客户端互通实测：误加 CFB 会触发 "unexpected response header"）
	innerPlain := []byte{responseHeaderByte, option, 0x00, 0x00}

	// 外层 18B 长度 AEAD
	lenKey := KDF16(responseBodyKey, KDFSaltConstAEADRespHeaderLenKey)
	lenIV := KDF(responseBodyIV, KDFSaltConstAEADRespHeaderLenIV)[:12]
	lb, _ := aes.NewCipher(lenKey)
	lg, _ := cipher.NewGCM(lb)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(innerPlain)))
	encLen := lg.Seal(nil, lenIV, l[:], nil)

	// 外层载荷 AEAD
	payKey := KDF16(responseBodyKey, KDFSaltConstAEADRespHeaderPayloadKey)
	payIV := KDF(responseBodyIV, KDFSaltConstAEADRespHeaderPayloadIV)[:12]
	pb, _ := aes.NewCipher(payKey)
	pg, _ := cipher.NewGCM(pb)
	encPay := pg.Seal(nil, payIV, innerPlain, nil)

	var out bytes.Buffer
	out.Write(encLen)
	out.Write(encPay)
	return out.Bytes()
}

func hx(b []byte) string { return hex.EncodeToString(b) }

var failed bool

func check(name string, ok bool) {
	if !ok {
		failed = true
		fmt.Printf("SELF_CHECK_FAIL %s\n", name)
	}
}

func main() {
	w := os.Stdout

	// ===== 固定输入（与设计文档一致）=====
	uuidHex := "de53e86485304212a3d7c31e60b62e91" // xray.json 中的 UUID 去横线
	uuidBytes, _ := hex.DecodeString(uuidHex)
	var t int64 = 1700000000
	var rnd = [4]byte{0x11, 0x22, 0x33, 0x44}
	nonce, _ := hex.DecodeString("0102030405060708")

	var requestBodyIV [16]byte
	var requestBodyKey [16]byte
	for i := 0; i < 16; i++ {
		requestBodyIV[i] = 0x11
		requestBodyKey[i] = 0x22
	}
	responseHeaderByte := byte(0x33)
	option := byte(0x04)       // RequestOptionChunkMasking
	paddingLen := byte(5)      // 0..15
	security := byte(3)        // AES128_GCM
	command := byte(0x01)      // TCP
	domain := "www.example.com" // 15 字节
	port := uint16(443)

	// ===== 1. cmdKey (common/protocol/id.go: NewID) =====
	var cmdKey [16]byte
	{
		h := md5.New()
		h.Write(uuidBytes)
		h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
		copy(cmdKey[:], h.Sum(nil))
	}

	// ===== 2. AuthID =====
	authID := CreateAuthIDFixed(cmdKey[:], t, rnd)

	// ===== 3. 请求头明文（encoding/client.go:63-102 序列化）=====
	var hb bytes.Buffer
	hb.WriteByte(0x01) // Version
	hb.Write(requestBodyIV[:])
	hb.Write(requestBodyKey[:])
	hb.WriteByte(responseHeaderByte)
	hb.WriteByte(option)
	hb.WriteByte(paddingLen<<4 | security)
	hb.WriteByte(0x00)
	hb.WriteByte(command)
	// 地址: 端口在前（PortThenAddress），2B BE + 类型 2 域名 1B 长度前缀
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	hb.Write(p[:])
	hb.WriteByte(0x02)
	hb.WriteByte(byte(len(domain)))
	hb.WriteString(domain)
	for i := 0; i < int(paddingLen); i++ {
		hb.WriteByte(0xAA)
	}
	fnv1a := fnv.New32a()
	fnv1a.Write(hb.Bytes())
	hb.Write(fnv1a.Sum(nil))
	headerPlain := hb.Bytes()

	// ===== 4. 密封后的完整请求头（线上字节）=====
	sealed := SealHeaderFixed(cmdKey, headerPlain, t, rnd, nonce)

	// ===== 5. 响应头 =====
	respHeader := ResponseHeaderFixed(requestBodyKey, requestBodyIV, responseHeaderByte, option)

	// ===== 6. VLESS 请求头（明文，无 addons，TCP）=====
	var vb bytes.Buffer
	vb.WriteByte(0x00) // version
	vb.Write(uuidBytes)
	vb.WriteByte(0x00) // addons length = 0
	vb.WriteByte(0x01) // command TCP
	vb.Write(p[:])     // port BE
	vb.WriteByte(0x02) // addr type domain
	vb.WriteByte(byte(len(domain)))
	vb.WriteString(domain)

	// ===== 输出 =====
	fmt.Fprintln(w, "UUID_BYTES", hx(uuidBytes))
	fmt.Fprintln(w, "CMD_KEY", hx(cmdKey[:]))
	fmt.Fprintln(w, "AUTH_ID", hx(authID[:]))
	fmt.Fprintln(w, "KDF16_AUTH_ID_KEY", hx(KDF16(cmdKey[:], KDFSaltConstAuthIDEncryptionKey)))
	fmt.Fprintln(w, "KDF16_HDR_LEN_KEY", hx(KDF16(cmdKey[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, string(authID[:]), string(nonce))))
	fmt.Fprintln(w, "KDF12_HDR_LEN_NONCE", hx(KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, string(authID[:]), string(nonce))[:12]))
	fmt.Fprintln(w, "KDF16_HDR_PAY_KEY", hx(KDF16(cmdKey[:], KDFSaltConstVMessHeaderPayloadAEADKey, string(authID[:]), string(nonce))))
	fmt.Fprintln(w, "KDF12_HDR_PAY_NONCE", hx(KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadAEADIV, string(authID[:]), string(nonce))[:12]))
	fmt.Fprintln(w, "REQ_HEADER_PLAIN", hx(headerPlain))
	fmt.Fprintln(w, "REQ_HEADER_PLAIN_LEN", fmt.Sprint(len(headerPlain)))
	fmt.Fprintln(w, "REQ_HEADER_SEALED", hx(sealed))
	fmt.Fprintln(w, "REQ_HEADER_SEALED_LEN", fmt.Sprint(len(sealed)))

	respBodyKeySum := sha256.Sum256(requestBodyKey[:])
	respBodyIVSum := sha256.Sum256(requestBodyIV[:])
	respBodyKey := respBodyKeySum[:16]
	respBodyIV := respBodyIVSum[:16]
	fmt.Fprintln(w, "RESP_BODY_KEY", hx(respBodyKey))
	fmt.Fprintln(w, "RESP_BODY_IV", hx(respBodyIV))
	fmt.Fprintln(w, "KDF16_RESP_LEN_KEY", hx(KDF16(respBodyKey, KDFSaltConstAEADRespHeaderLenKey)))
	fmt.Fprintln(w, "KDF12_RESP_LEN_IV", hx(KDF(respBodyIV, KDFSaltConstAEADRespHeaderLenIV)[:12]))
	fmt.Fprintln(w, "KDF16_RESP_PAY_KEY", hx(KDF16(respBodyKey, KDFSaltConstAEADRespHeaderPayloadKey)))
	fmt.Fprintln(w, "KDF12_RESP_PAY_IV", hx(KDF(respBodyIV, KDFSaltConstAEADRespHeaderPayloadIV)[:12]))
	fmt.Fprintln(w, "RESP_HEADER_WIRE", hx(respHeader))
	fmt.Fprintln(w, "RESP_HEADER_WIRE_LEN", fmt.Sprint(len(respHeader)))

	fmt.Fprintln(w, "VLESS_REQ_HEADER", hx(vb.Bytes()))

	// ===== 自校验 =====
	// a) AuthID 解码 CRC
	{
		block, _ := aes.NewCipher(KDF16(cmdKey[:], KDFSaltConstAuthIDEncryptionKey))
		var dec [16]byte
		block.Decrypt(dec[:], authID[:])
		crc := crc32.ChecksumIEEE(dec[:12])
		check("authid_crc", binary.BigEndian.Uint32(dec[12:16]) == crc)
	}
	// b) 密封头可开且还原
	{
		var k16 [16]byte
		copy(k16[:], cmdKey[:])
		var a16 [16]byte
		copy(a16[:], sealed[:16])
		pt, err := OpenHeaderFixed(k16, a16, sealed[16:])
		check("sealed_open", err == nil && bytes.Equal(pt, headerPlain))
	}
	// c) 响应头 AEAD 外层可开（内层为明文，无 CFB）
	{
		respKeySum := sha256.Sum256(requestBodyKey[:])
		respIVSum := sha256.Sum256(requestBodyIV[:])
		bodyKey := respKeySum[:16]
		bodyIV := respIVSum[:16]
		encLen := respHeader[:18]
		encPay := respHeader[18:]
		lk := KDF16(bodyKey, KDFSaltConstAEADRespHeaderLenKey)
		ln := KDF(bodyIV, KDFSaltConstAEADRespHeaderLenIV)[:12]
		lb, _ := aes.NewCipher(lk)
		lg, _ := cipher.NewGCM(lb)
		lpt, err := lg.Open(nil, ln, encLen, nil)
		check("resp_len_open", err == nil)
		length := binary.BigEndian.Uint16(lpt)
		pk := KDF16(bodyKey, KDFSaltConstAEADRespHeaderPayloadKey)
		pn := KDF(bodyIV, KDFSaltConstAEADRespHeaderPayloadIV)[:12]
		pbl, _ := aes.NewCipher(pk)
		pg, _ := cipher.NewGCM(pbl)
		inner, err := pg.Open(nil, pn, encPay, nil)
		check("resp_pay_open", err == nil && int(length) == len(inner))
		check("resp_inner_plain", bytes.Equal(inner, []byte{responseHeaderByte, option, 0x00, 0x00}))
	}
	if failed {
		fmt.Fprintln(w, "SELF_CHECK FAILED")
		os.Exit(1)
	}
	fmt.Fprintln(w, "SELF_CHECK PASSED")
}
