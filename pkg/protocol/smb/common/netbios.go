package common

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

type NetBIOSConn interface {
	io.Reader
	io.Writer
}

const maxNetBIOSSize = 0x00FFFFFF

func SendNetBIOSMessage(conn NetBIOSConn, data []byte) error {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}

	if _, err := conn.Write(append(buf.Bytes(), data...)); err != nil {
		return err
	}

	rw, ok := conn.(interface{ Flush() error })
	if ok {
		if err := rw.Flush(); err != nil {
			return err
		}
	}

	return nil
}

func ReceiveNetBIOSMessage(conn NetBIOSConn) ([]byte, error) {
	var size uint32
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return nil, err
	}

	if size > maxNetBIOSSize {
		return nil, errors.New("invalid NetBIOS session message")
	}

	data := make([]byte, size)
	l, err := io.ReadFull(conn, data)
	if err != nil {
		return nil, err
	}

	if uint32(l) != size {
		return nil, errors.New("message size invalid")
	}

	return data, nil
}

func NewReadWriter(conn NetBIOSConn) *bufio.ReadWriter {
	return bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
}
