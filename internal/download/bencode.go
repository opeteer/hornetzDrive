package download

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// UnmarshalBencode parses bencoded data into Go types:
// strings are returned as string (or []byte if invalid UTF-8/binary),
// integers as int64, lists as []interface{}, and dicts as map[string]interface{}.
func UnmarshalBencode(data []byte) (interface{}, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	val, err := decodeValue(reader)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func decodeValue(r *bufio.Reader) (interface{}, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	switch {
	case b == 'i':
		return decodeInt(r)
	case b == 'l':
		return decodeList(r)
	case b == 'd':
		return decodeDict(r)
	case b >= '0' && b <= '9':
		_ = r.UnreadByte()
		return decodeString(r)
	default:
		return nil, fmt.Errorf("bencode: unexpected token '%c'", b)
	}
}

func decodeInt(r *bufio.Reader) (int64, error) {
	buf := make([]byte, 0, 20)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if b == 'e' {
			break
		}
		buf = append(buf, b)
	}
	return strconv.ParseInt(string(buf), 10, 64)
}

func decodeString(r *bufio.Reader) (string, error) {
	lenBuf := make([]byte, 0, 10)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == ':' {
			break
		}
		if b < '0' || b > '9' {
			return "", errors.New("bencode: invalid string length")
		}
		lenBuf = append(lenBuf, b)
	}

	strLen, err := strconv.ParseInt(string(lenBuf), 10, 64)
	if err != nil || strLen < 0 {
		return "", errors.New("bencode: invalid string length")
	}

	buf := make([]byte, strLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func decodeList(r *bufio.Reader) ([]interface{}, error) {
	var list []interface{}
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == 'e' {
			break
		}
		_ = r.UnreadByte()

		item, err := decodeValue(r)
		if err != nil {
			return nil, err
		}
		list = append(list, item)
	}
	return list, nil
}

func decodeDict(r *bufio.Reader) (map[string]interface{}, error) {
	dict := make(map[string]interface{})
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == 'e' {
			break
		}
		_ = r.UnreadByte()

		key, err := decodeString(r)
		if err != nil {
			return nil, err
		}

		val, err := decodeValue(r)
		if err != nil {
			return nil, err
		}
		dict[key] = val
	}
	return dict, nil
}

// MarshalBencode encodes Go values into bencoded format.
func MarshalBencode(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeValue(w *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case string:
		fmt.Fprintf(w, "%d:%s", len(val), val)
	case []byte:
		fmt.Fprintf(w, "%d:", len(val))
		w.Write(val)
	case int:
		fmt.Fprintf(w, "i%de", val)
	case int64:
		fmt.Fprintf(w, "i%de", val)
	case []interface{}:
		w.WriteByte('l')
		for _, item := range val {
			if err := encodeValue(w, item); err != nil {
				return err
			}
		}
		w.WriteByte('e')
	case map[string]interface{}:
		w.WriteByte('d')
		// Bencode requires dictionary keys to be sorted lexicographically
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "%d:%s", len(k), k)
			if err := encodeValue(w, val[k]); err != nil {
				return err
			}
		}
		w.WriteByte('e')
	default:
		return fmt.Errorf("bencode: unsupported type %T", v)
	}
	return nil
}
