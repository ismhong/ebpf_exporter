package decoder

import (
	"binary"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/ismhong/ebpf_exporter/config"
)

func GetHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

// UInt is a decoder that transforms unsigned integers into their string values
type UInt struct{}

// Decode transforms unsigned integers into their string values
func (u *UInt) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	byteOrder := GetHostByteOrder()

	result := uint64(0)

	switch len(in) {
	case 8:
		result = byteOrder.Uint64(in)
	case 4:
		result = uint64(byteOrder.Uint32(in))
	case 2:
		result = uint64(byteOrder.Uint16(in))
	case 1:
		result = uint64(in[0])
	default:
		return nil, fmt.Errorf("unknown value length %d for %#v", len(in), in)
	}

	return []byte(strconv.Itoa(int(result))), nil
}
