package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"webscan/internal/common"
)

// Agent payload identity excludes metadata added by a receiving center. Use
// the same number-preserving canonical format as the released v2 receiver.
func canonicalEvent(p common.Map) (common.Map, string, error) {
	clean := common.Map{}
	for k, v := range p {
		if k != "server_ip" && k != "server_name" && k != "received_time" {
			clean[k] = v
		}
	}
	if !eventJSONCompatible(clean) {
		return nil, "", errors.New("事件载荷包含数据库不支持的文本或数字")
	}
	raw, err := common.Canonical(clean, false)
	if err != nil {
		return nil, "", errors.New("事件载荷不能生成兼容摘要")
	}
	return clean, digest(raw), nil
}

// JSON permits NUL strings and integers larger than PostgreSQL numeric. Reject
// these permanently before opening an event insert so a bad item cannot abort
// the transaction containing otherwise valid events.
func eventJSONCompatible(v any) bool {
	switch x := v.(type) {
	case string:
		return utf8.ValidString(x) && !strings.ContainsRune(x, 0)
	case json.Number:
		number := strings.TrimPrefix(string(x), "-")
		exponent := int64(0)
		if index := strings.IndexAny(number, "eE"); index >= 0 {
			var err error
			exponent, err = strconv.ParseInt(number[index+1:], 10, 64)
			if err != nil || exponent < -200000 || exponent > 200000 {
				return false
			}
			number = number[:index]
		}
		before, after := len(number), 0
		if index := strings.IndexByte(number, '.'); index >= 0 {
			before, after = index, len(number)-index-1
			number = number[:index] + number[index+1:]
		}
		leading := len(number) - len(strings.TrimLeft(number, "0"))
		return int64(before-leading)+exponent <= 131072 && int64(after)-exponent <= 16383
	case common.Map:
		for k, value := range x {
			if !eventJSONCompatible(k) || !eventJSONCompatible(value) {
				return false
			}
		}
	case []any:
		for _, value := range x {
			if !eventJSONCompatible(value) {
				return false
			}
		}
	}
	return true
}

func eventText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// Early local v3 databases used a JSON/float64 digest. Only accept that
// weaker receipt when its retained payload also matches PostgreSQL's exact
// numeric value; a rounded large integer must not acknowledge another event.
func matchesEventReceipt(ctx context.Context, tx *sql.Tx, node, id, hash string, raw []byte, payload common.Map) (bool, error) {
	var stored, format string
	if err := tx.QueryRowContext(ctx, "SELECT digest,digest_format FROM v3_event_keys WHERE node=$1 AND id=$2", node, id).Scan(&stored, &format); err != nil {
		return false, err
	}
	if format == "canonical-v1" {
		return stored == hash, nil
	}
	if format != "v3-json-v1" {
		return false, errors.New("事件摘要版本不受支持")
	}
	var old common.Map
	if json.Unmarshal(raw, &old) != nil || stored != digest(common.JSON(old)) {
		return false, nil
	}
	var same bool
	err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_events WHERE node=$1 AND id=$2 AND payload=$3::jsonb)", node, id, common.JSON(payload)).Scan(&same)
	return same, err
}
