package main

import (
	"fmt"
	"encoding/hex"
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
)

type Key struct {
	Data [52]byte
}

func (k *Key) Init() {
	k.Data = [52]byte{
		0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
		0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
		0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
		0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
		0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
}

func (k *Key) Shift() {
	j := k.Data[0] >> 7
	for i := 0; i < len(k.Data) - 1; i++ {
		k.Data[i] = (k.Data[i] << 1) | (k.Data[i+1] >> 7)
	}

	k.Data[51] = (k.Data[51] << 1) | j
}

func (k Key) LeftMost32BitsKey() uint32 {
	i := uint32(k.Data[0]) << 24 | uint32(k.Data[1]) << 16 | uint32(k.Data[2]) << 8 | uint32(k.Data[3])
	return i
}

type Result struct {
	Value uint32
}

func (r Result) Bytes() []byte {
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, &r)
	return buf.Bytes()
}

func (r Result) HexString() string {
	return fmt.Sprintf("0x%s", hex.EncodeToString(r.Bytes()))
}

func ComputeHash(input []byte) Result {
	key := Key{}
	key.Init()

	res := Result{0}

	for _, b := range input {
		for i := 7; i >= 0; i-- {
			if ((b >> uint(i)) & 1) == 1 {
				res.Value ^= key.LeftMost32BitsKey()
			}
			key.Shift()
		}
	}

	return res
}

func reverse(b []byte) {
	for i, j := 0, len(b) - 1; i < j; i, j = i + 1, j - 1 {
		b[i], b[j] = b[j], b[i]
	}
}

func IPToByte(ip string, af int) []byte {
	b := net.ParseIP(ip)

	if af == syscall.AF_INET && len(b) == 16 {
		b = b[12:]
	}

	// reverse(b)

	return b
}

func PortToByte(port uint16) []byte {
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, &port)
	return buf.Bytes()
}

func Input(ip1, ip2, port1, port2 []byte) []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.Write(ip1)
	buf.Write(ip2)
	buf.Write(port1)
	buf.Write(port2)
	return buf.Bytes()
}

func main() {
	ip1 := "3ffe:2501:200:1fff::7"
	ip2 := "3ffe:2501:200:3::1"
	port1 := 2794
	port2 := 1766

	in := Input(IPToByte(ip1, syscall.AF_INET6), IPToByte(ip2, syscall.AF_INET6), PortToByte(uint16(port1)), PortToByte(uint16(port2)))
	res := ComputeHash(in)

	fmt.Print(res.HexString())

}
