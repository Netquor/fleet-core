package mongodb

import (
	"math"

	"github.com/micromdm/plist"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// plistDoc turns a property list (what a device sends, and what a command is) into a value BSON stores natively, so its contents can be queried, indexed and watched:
// dictionaries become documents, arrays arrays, <integer> int64, <real> double, <true/> and <false/> booleans, <date> a datetime and <data> binary.
// The raw XML is always kept beside it (it is the source of truth: it is what gets sent to a device and what a migration replays); this is a convenience copy,
// so a plist that will not parse (or holds something BSON cannot) gives nil and the raw is stored alone.
func plistDoc(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := plist.Unmarshal(raw, &v); err != nil {
		return nil
	}
	out, ok := normalize(v)
	if !ok {
		return nil
	}
	// A BSON document needs a dictionary at the top (a plist's root always is one for MDM messages).
	if _, isDoc := out.(bson.M); !isDoc {
		return nil
	}
	return out
}

func normalize(v any) (any, bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		m := make(bson.M, len(t))
		for k, e := range t {
			n, ok := normalize(e)
			if !ok {
				return nil, false
			}
			m[k] = n
		}
		return m, true
	case []interface{}:
		a := make(bson.A, len(t))
		for i, e := range t {
			n, ok := normalize(e)
			if !ok {
				return nil, false
			}
			a[i] = n
		}
		return a, true
	case uint64:
		if t > math.MaxInt64 {
			return float64(t), true
		}
		return int64(t), true
	case uint:
		return normalize(uint64(t))
	case int:
		return int64(t), true
	case int8, int16, int32, int64, float32, float64, bool, string, []byte:
		return t, true
	case nil:
		return nil, true
	default:
		// time.Time and anything else the driver can encode on its own.
		return t, true
	}
}

// lit makes a value a literal inside an aggregation-pipeline update, where a string such as "$topic" would otherwise be read as a field path.
func lit(v any) bson.D { return bson.D{{Key: "$literal", Value: v}} }
