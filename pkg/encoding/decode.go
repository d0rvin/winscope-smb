package encoding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
)

func Unmarshal(buf []byte, v any) error {
	_, err := unmarshal(buf, v, nil)
	return err
}

func unmarshal(buf []byte, v any, meta *Metadata) (any, error) {
	if bm, ok := v.(BinaryMarshallable); ok {
		return unmarshalBinaryMarshallable(bm, buf, meta)
	}

	typev, valuev, err := resolveTypeAndValue(v)
	if err != nil {
		return nil, err
	}

	meta = ensureMetadata(meta, v, buf)

	switch typev.Kind() {
	case reflect.Uint8:
		return unmarshalUint8(buf, meta)
	case reflect.Uint16:
		return unmarshalUint16(buf, meta)
	case reflect.Uint32:
		return unmarshalUint32(buf, meta)
	case reflect.Uint64:
		return unmarshalUint64(buf, meta)
	case reflect.String:
		return unmarshalString(buf, meta)
	case reflect.Struct:
		return unmarshalStruct(buf, typev, valuev, meta)
	case reflect.Slice, reflect.Array:
		return unmarshalSlice(buf, typev, meta)
	default:
		return nil, fmt.Errorf("unmarshal not implemented for kind: %s", typev.Kind().String())
	}
}

func unmarshalBinaryMarshallable(bm BinaryMarshallable, buf []byte, meta *Metadata) (any, error) {
	n, err := bm.UnmarshalBinary(buf, meta)
	if err != nil {
		return nil, err
	}
	if meta != nil {
		meta.CurrOffset += n
	}
	return bm, nil
}

func resolveTypeAndValue(v any) (reflect.Type, reflect.Value, error) {
	typev := reflect.TypeOf(v)
	valuev := reflect.ValueOf(v)

	if typev.Kind() == reflect.Ptr {
		vv := reflect.ValueOf(v)
		if vv.IsNil() {
			if !vv.CanSet() {
				return nil, reflect.Value{}, errors.New("cannot set new value to nil pointer")
			}
			newElem := reflect.New(vv.Type().Elem())
			vv.Set(newElem)
			vv = newElem
		}
		valuev = vv.Elem()
		typev = valuev.Type()
	}

	if typev.Kind() == reflect.Interface {
		if valuev.IsNil() {
			return nil, reflect.Value{}, errors.New("cannot set new value to nil pointer")
		}
		valuev = valuev.Elem()
		typev = valuev.Type()
		return typev, valuev, nil
	}

	return typev, valuev, nil
}

func ensureMetadata(meta *Metadata, v any, buf []byte) *Metadata {
	if meta != nil {
		return meta
	}
	return &Metadata{
		Tags:       &TagMap{},
		Lens:       make(map[string]int),
		Parent:     v,
		ParentBuf:  buf,
		Offsets:    make(map[string]int),
		CurrOffset: 0,
	}
}

func unmarshalUint8(buf []byte, meta *Metadata) (any, error) {
	var ret uint8
	if err := binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &ret); err != nil {
		return nil, err
	}
	meta.CurrOffset += binary.Size(ret)
	return ret, nil
}

func unmarshalUint16(buf []byte, meta *Metadata) (any, error) {
	var ret uint16
	if err := binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &ret); err != nil {
		return nil, err
	}
	if meta.Tags.Has("len") {
		ref, err := meta.Tags.GetString("len")
		if err != nil {
			return nil, err
		}
		meta.Lens[ref] = int(ret)
	}
	meta.CurrOffset += binary.Size(ret)
	return ret, nil
}

func unmarshalUint32(buf []byte, meta *Metadata) (any, error) {
	var ret uint32
	if err := binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &ret); err != nil {
		return nil, err
	}
	if meta.Tags.Has(TagOffset) {
		ref, err := meta.Tags.GetString(TagOffset)
		if err != nil {
			return nil, err
		}
		meta.Offsets[ref] = int(ret)
	}
	meta.CurrOffset += binary.Size(ret)
	return ret, nil
}

func unmarshalUint64(buf []byte, meta *Metadata) (any, error) {
	var ret uint64
	if err := binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &ret); err != nil {
		return nil, err
	}
	meta.CurrOffset += binary.Size(ret)
	return ret, nil
}

func unmarshalString(buf []byte, meta *Metadata) (any, error) {
	r := bytes.NewReader(buf)
	var data []byte
	for {
		var ch uint8
		if err := binary.Read(r, binary.LittleEndian, &ch); err != nil {
			return nil, err
		}
		meta.CurrOffset += 1
		if ch == 0 {
			break
		}
		data = append(data, ch)
	}
	return data, nil
}

func unmarshalStruct(buf []byte, typev reflect.Type, valuev reflect.Value, meta *Metadata) (any, error) {
	v := valuev.Addr().Interface()
	m := &Metadata{
		Tags:       &TagMap{},
		Lens:       make(map[string]int),
		Parent:     v,
		ParentBuf:  meta.ParentBuf,
		Offsets:    make(map[string]int),
		CurrOffset: 0,
	}

	for i := 0; i < typev.NumField(); i++ {
		field := typev.Field(i)
		m.CurrField = field.Name

		tags, err := parseTags(field)
		if err != nil {
			return nil, err
		}
		m.Tags = tags

		data, err := unmarshalStructField(buf, m, field, valuev.Field(i))
		if err != nil {
			return nil, err
		}
		valuev.Field(i).Set(reflect.ValueOf(data))
	}

	result := reflect.Indirect(reflect.ValueOf(v)).Interface()
	meta.CurrOffset += m.CurrOffset
	return result, nil
}

func unmarshalStructField(buf []byte, m *Metadata, field reflect.StructField, fieldValue reflect.Value) (any, error) {
	switch field.Type.Kind() {
	case reflect.Struct:
		return unmarshal(buf[m.CurrOffset:], fieldValue.Addr().Interface(), m)
	case reflect.String:
		data, err := unmarshal(buf[m.CurrOffset:], fieldValue.Addr().Interface(), m)
		if err != nil {
			return nil, err
		}
		if bytes, ok := data.([]byte); ok {
			return string(bytes), nil
		}
		return nil, fmt.Errorf("expected []byte, got %T", data)
	case reflect.Pointer:
		elemType := fieldValue.Type().Elem()
		if fieldValue.IsNil() {
			fieldValue.Set(reflect.New(elemType))
		}
		result, err := unmarshal(buf[m.CurrOffset:], fieldValue.Interface(), m)
		if err != nil {
			return nil, err
		}
		if reflect.TypeOf(result).Kind() != reflect.Ptr {
			fieldValue.Elem().Set(reflect.ValueOf(result))
		} else {
			fieldValue.Set(reflect.ValueOf(result))
		}
		return fieldValue.Interface(), nil
	default:
		if fieldValue.CanAddr() {
			if _, ok := fieldValue.Addr().Interface().(BinaryMarshallable); ok {
				data, err := unmarshal(buf[m.CurrOffset:], fieldValue.Addr().Interface(), m)
				if err != nil {
					return nil, err
				}
				dataValue := reflect.ValueOf(data)
				if dataValue.Kind() == reflect.Ptr {
					dataValue = dataValue.Elem()
				}
				return dataValue.Interface(), nil
			}
		}
		return unmarshal(buf[m.CurrOffset:], fieldValue.Interface(), m)
	}
}

func unmarshalSlice(buf []byte, typev reflect.Type, meta *Metadata) (any, error) {
	if meta.Tags.Has(TagPad) {
		return unmarshalPad(buf, meta)
	}

	switch typev.Elem().Kind() {
	case reflect.Uint8:
		return unmarshalUint8Slice(buf, meta)
	default:
		return nil, fmt.Errorf("unmarshal not implemented for slice kind: %s", typev.Kind().String())
	}
}

func unmarshalPad(buf []byte, meta *Metadata) (any, error) {
	var padBytes int
	for _, data := range buf {
		if data != 0x00 {
			break
		}
		padBytes++
	}
	data := buf[:padBytes]
	meta.CurrOffset += padBytes
	return data, nil
}

func unmarshalUint8Slice(buf []byte, meta *Metadata) (any, error) {
	length, r, err := resolveSliceParams(buf, meta)
	if err != nil {
		return nil, err
	}

	data := make([]byte, length)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func resolveSliceParams(buf []byte, meta *Metadata) (int, *bytes.Buffer, error) {
	var length, offset int

	if meta.Tags.Has(TagFixed) {
		var err error
		if length, err = meta.Tags.GetInt(TagFixed); err != nil {
			return 0, nil, err
		}
		if length < 0 || length > len(buf) {
			return 0, nil, fmt.Errorf("slice length out of bounds: %d (buf len %d)", length, len(buf))
		}
		meta.CurrOffset += length
		return length, bytes.NewBuffer(buf[:length]), nil
	}

	if val, ok := meta.Lens[meta.CurrField]; ok {
		length = val
	} else {
		return 0, nil, fmt.Errorf("variable length field missing length reference in struct: %s", meta.CurrField)
	}

	if val, ok := meta.Offsets[meta.CurrField]; ok {
		offset = val
	} else {
		offset = meta.CurrOffset
		meta.CurrOffset += length
	}

	if meta.ParentBuf == nil {
		return 0, nil, errors.New("missing parent buffer for slice decode")
	}
	if offset < 0 || length < 0 || offset+length > len(meta.ParentBuf) {
		return 0, nil, fmt.Errorf("slice out of bounds: offset=%d length=%d buf len=%d", offset, length, len(meta.ParentBuf))
	}
	return length, bytes.NewBuffer(meta.ParentBuf[offset:offset+length]), nil
}
