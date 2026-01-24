package encoding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
)

func Marshal(v any) ([]byte, error) {
	return marshal(v, nil)
}

func marshal(v any, meta *Metadata) ([]byte, error) {
	if buf, err := marshalBinaryMarshallable(v, meta); err == nil {
		return buf, nil
	}

	typev, valuev, err := resolveMarshalTypeAndValue(v)
	if err != nil {
		return nil, err
	}

	switch typev.Kind() {
	case reflect.Struct:
		return marshalStruct(valuev, v)
	case reflect.Slice, reflect.Array:
		return marshalSlice(typev, v)
	case reflect.Uint8:
		return marshalUint8(valuev)
	case reflect.Uint16:
		return marshalUint16(valuev, meta)
	case reflect.Uint32:
		return marshalUint32(valuev, meta)
	case reflect.Uint64:
		return marshalUint64(valuev)
	default:
		return nil, fmt.Errorf("marshal not implemented for kind: %s", typev.Kind())
	}
}

func marshalBinaryMarshallable(v any, meta *Metadata) ([]byte, error) {
	bm, ok := v.(BinaryMarshallable)
	if !ok {
		return nil, errors.New("not a binary marshallable")
	}
	buf, err := bm.MarshalBinary(meta)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func resolveMarshalTypeAndValue(v any) (reflect.Type, reflect.Value, error) {
	typev := reflect.TypeOf(v)
	valuev := reflect.ValueOf(v)

	if typev.Kind() == reflect.Ptr {
		valuev = reflect.Indirect(reflect.ValueOf(v))
		typev = valuev.Type()
	}
	return typev, valuev, nil
}

func marshalStruct(valuev reflect.Value, parent any) ([]byte, error) {
	typev := valuev.Type()
	m := &Metadata{
		Tags:   &TagMap{},
		Lens:   make(map[string]int),
		Parent: parent,
	}
	w := bytes.NewBuffer(nil)
	for j := 0; j < valuev.NumField(); j++ {
		tags, err := parseTags(typev.Field(j))
		if err != nil {
			return nil, err
		}
		m.Tags = tags
		buf, err := marshal(valuev.Field(j).Interface(), m)
		if err != nil {
			return nil, err
		}
		m.Lens[typev.Field(j).Name] = len(buf)
		if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func marshalSlice(typev reflect.Type, v any) ([]byte, error) {
	w := bytes.NewBuffer(nil)
	switch typev.Elem().Kind() {
	case reflect.Uint8:
		if err := binary.Write(w, binary.LittleEndian, v.([]uint8)); err != nil {
			return nil, err
		}
	case reflect.Uint16:
		if err := binary.Write(w, binary.LittleEndian, v.([]uint16)); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("marshal not implemented for slice kind: %s", typev.Elem().Kind())
	}
	return w.Bytes(), nil
}

func marshalUint8(valuev reflect.Value) ([]byte, error) {
	val, ok := valuev.Interface().(uint8)
	if !ok {
		return nil, fmt.Errorf("invalid type for uint8: %T", valuev.Interface())
	}
	w := bytes.NewBuffer(nil)
	if err := binary.Write(w, binary.LittleEndian, val); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func marshalUint16(valuev reflect.Value, meta *Metadata) ([]byte, error) {
	data, ok := valuev.Interface().(uint16)
	if !ok {
		return nil, fmt.Errorf("invalid type for uint16: %T", valuev.Interface())
	}
	if meta != nil {
		if meta.Tags.Has("len") {
			fieldName, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			l, err := getFieldLengthByName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint16(l)
		}
		if meta.Tags.Has("offset") {
			fieldName, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			l, err := getOffsetByFieldName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint16(l)
		}
	}
	w := bytes.NewBuffer(nil)
	if err := binary.Write(w, binary.LittleEndian, data); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func marshalUint32(valuev reflect.Value, meta *Metadata) ([]byte, error) {
	data, ok := valuev.Interface().(uint32)
	if !ok {
		return nil, fmt.Errorf("invalid type for uint32: %T", valuev.Interface())
	}
	if meta != nil {
		if meta.Tags.Has("len") {
			fieldName, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			l, err := getFieldLengthByName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint32(l)
		}
		if meta.Tags.Has("offset") {
			fieldName, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			l, err := getOffsetByFieldName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint32(l)
		}
	}
	w := bytes.NewBuffer(nil)
	if err := binary.Write(w, binary.LittleEndian, data); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func marshalUint64(valuev reflect.Value) ([]byte, error) {
	val, ok := valuev.Interface().(uint64)
	if !ok {
		return nil, fmt.Errorf("invalid type for uint64: %T", valuev.Interface())
	}
	w := bytes.NewBuffer(nil)
	if err := binary.Write(w, binary.LittleEndian, val); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func getOffsetByFieldName(fieldName string, meta *Metadata) (int, error) {
	if meta == nil || meta.Tags == nil || meta.Parent == nil || meta.Lens == nil {
		return 0, errors.New("cannot determine field offset. missing required metadata")
	}
	var ret int
	var found bool
	parentvf := reflect.Indirect(reflect.ValueOf(meta.Parent))
	// To determine offset, we loop through all fields of the struct, summing lengths of previous elements
	// until we reach our field
	for i := 0; i < parentvf.NumField(); i++ {
		tf := parentvf.Type().Field(i)
		if tf.Name == fieldName {
			found = true
			break
		}
		if l, ok := meta.Lens[tf.Name]; ok {
			// Length of field is in cache
			ret += l
		} else {
			// Not in cache. Must marshal field to determine length. Add to cache after
			buf, err := Marshal(parentvf.Field(i).Interface())
			if err != nil {
				return 0, err
			}
			l := len(buf)
			meta.Lens[tf.Name] = l
			ret += l
		}
	}
	if !found {
		return 0, fmt.Errorf("cannot find field name within struct: %s", fieldName)
	}
	return ret, nil
}

func getFieldLengthByName(fieldName string, meta *Metadata) (int, error) {
	var ret int
	if meta == nil || meta.Tags == nil || meta.Parent == nil || meta.Lens == nil {
		return 0, errors.New("cannot determine field length. missing required metadata")
	}

	// Check if length is stored in field length cache
	if val, ok := meta.Lens[fieldName]; ok {
		return val, nil
	}

	parentvf := reflect.Indirect(reflect.ValueOf(meta.Parent))

	field := parentvf.FieldByName(fieldName)
	if !field.IsValid() {
		return 0, errors.New("invalid field. cannot determine length")
	}

	bm, ok := field.Interface().(BinaryMarshallable)
	if ok {
		// Custom marshallable interface found.
		buf, err := bm.MarshalBinary(meta)
		if err != nil {
			return 0, err
		}
		return len(buf), nil
	}

	if field.Kind() == reflect.Ptr {
		field = field.Elem()
	}

	switch field.Kind() {
	case reflect.Struct:
		buf, err := Marshal(field.Interface())
		if err != nil {
			return 0, err
		}
		ret = len(buf)
	case reflect.Interface:
		return 0, errors.New("interface length calculation not implemented")
	case reflect.Slice, reflect.Array:
		switch field.Type().Elem().Kind() {
		case reflect.Uint8:
			ret = len(field.Interface().([]byte))
		default:
			return 0, fmt.Errorf("cannot calculate the length of unknown slice type for %s", fieldName)
		}
	case reflect.Uint8:
		ret = binary.Size(field.Interface().(uint8))
	case reflect.Uint16:
		ret = binary.Size(field.Interface().(uint16))
	case reflect.Uint32:
		ret = binary.Size(field.Interface().(uint32))
	case reflect.Uint64:
		ret = binary.Size(field.Interface().(uint64))
	default:
		return 0, fmt.Errorf("cannot calculate the length of unknown kind for field %s", fieldName)
	}
	meta.Lens[fieldName] = ret
	return ret, nil
}
