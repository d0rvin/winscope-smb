package encoding

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type BinaryMarshallable interface {
	MarshalBinary(*Metadata) ([]byte, error)
	UnmarshalBinary([]byte, *Metadata) (int, error)
}

const (
	TagKey = "smb"

	TagFixed  = "fixed"
	TagOffset = "offset"
	TagLen    = "len"
	TagASN1   = "asn1"
	TagPad    = "pad"
)

type Metadata struct {
	Tags       *TagMap
	Lens       map[string]int
	Offsets    map[string]int
	Parent     any
	ParentBuf  []byte
	CurrOffset int
	CurrField  string
}

type TagMap struct {
	m   map[string]any
	has map[string]bool
}

func (t TagMap) Has(key string) bool {
	return t.has[key]
}

func (t TagMap) Set(key string, val any) {
	t.m[key] = val
	t.has[key] = true
}

func (t TagMap) Get(key string) any {
	return t.m[key]
}

func (t TagMap) GetInt(key string) (int, error) {
	if !t.Has(key) {
		return 0, errors.New("key does not exist in tag")
	}
	val, ok := t.Get(key).(int)
	if !ok {
		return 0, fmt.Errorf("value for key %s is not an int", key)
	}
	return val, nil
}

func (t TagMap) GetString(key string) (string, error) {
	if !t.Has(key) {
		return "", errors.New("key does not exist in tag")
	}
	val, ok := t.Get(key).(string)
	if !ok {
		return "", fmt.Errorf("value for key %s is not a string", key)
	}
	return val, nil
}

func parseTags(sf reflect.StructField) (*TagMap, error) {
	ret := &TagMap{
		m:   make(map[string]any),
		has: make(map[string]bool),
	}
	tag := sf.Tag.Get(TagKey)
	smbTags := strings.SplitSeq(tag, ",")
	for smbTag := range smbTags {
		tokens := strings.Split(smbTag, ":")
		switch tokens[0] {
		case TagLen, TagOffset:
			if len(tokens) != 2 {
				return nil, errors.New("missing required tag data. expecting key:val")
			}
			ret.Set(tokens[0], tokens[1])
		case TagFixed:
			if len(tokens) != 2 {
				return nil, errors.New("missing required tag data. expecting key:val")
			}
			i, err := strconv.Atoi(tokens[1])
			if err != nil {
				return nil, err
			}
			ret.Set(tokens[0], i)
		case TagASN1:
			ret.Set(tokens[0], true)
		case TagPad:
			ret.Set(tokens[0], true)
		}
	}

	return ret, nil
}
