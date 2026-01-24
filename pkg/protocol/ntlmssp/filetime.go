package ntlmssp

import (
	"encoding/binary"
	"time"
)

type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func (ft *Filetime) Nanoseconds() int64 {
	// 100-nanosecond intervals since January 1, 1601
	nsec := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime)
	// change starting time to the Epoch (00:00:00 UTC, January 1, 1970)
	nsec -= 116444736000000000
	// convert into nanoseconds
	nsec *= 100
	return nsec
}

func FileTimeToSystemTime(t []byte) time.Time {
	ft := &Filetime{
		LowDateTime:  binary.LittleEndian.Uint32(t[:4]),
		HighDateTime: binary.LittleEndian.Uint32(t[4:]),
	}
	return time.Unix(0, ft.Nanoseconds())
}
