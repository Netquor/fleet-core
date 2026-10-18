package mongodb

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

const sample = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CommandUUID</key><string>abc-123</string>
  <key>Status</key><string>Acknowledged</string>
  <key>SecurityInfo</key><dict><key>FDE_Enabled</key><true/><key>PasscodePresent</key><false/><key>Count</key><integer>7</integer><key>Ratio</key><real>0.5</real></dict>
  <key>Apps</key><array><dict><key>Identifier</key><string>com.apple.Safari</string></dict><dict><key>Identifier</key><string>com.apple.finder</string></dict></array>
  <key>When</key><date>2026-10-18T14:00:00Z</date>
  <key>Blob</key><data>aGVsbG8=</data>
  <key>Dollar</key><string>$topic</string>
  <key>com.example.dotted</key><string>ok</string>
</dict></plist>`

func TestPlistDoc(t *testing.T) {
	v := plistDoc([]byte(sample))
	m, ok := v.(bson.M)
	if !ok {
		t.Fatalf("not a document: %T", v)
	}
	if m["Status"] != "Acknowledged" || m["Dollar"] != "$topic" || m["com.example.dotted"] != "ok" {
		t.Errorf("strings: %v", m)
	}
	si := m["SecurityInfo"].(bson.M)
	if si["FDE_Enabled"] != true || si["PasscodePresent"] != false || si["Count"] != int64(7) || si["Ratio"] != 0.5 {
		t.Errorf("security info: %#v", si)
	}
	apps := m["Apps"].(bson.A)
	if len(apps) != 2 || apps[1].(bson.M)["Identifier"] != "com.apple.finder" {
		t.Errorf("apps: %v", apps)
	}
	if d, _ := m["When"].(time.Time); !d.Equal(time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC)) {
		t.Errorf("date: %v", m["When"])
	}
	if b, _ := m["Blob"].([]byte); string(b) != "hello" {
		t.Errorf("data: %v", m["Blob"])
	}
	// It must survive a round trip through BSON itself.
	raw, err := bson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back bson.M
	if err := bson.Unmarshal(raw, &back); err != nil || back["CommandUUID"] != "abc-123" {
		t.Fatalf("bson round trip: %v %v", err, back)
	}
}

func TestPlistDocNotUsable(t *testing.T) {
	for name, raw := range map[string]string{"empty": "", "not xml": "hello", "array root": `<?xml version="1.0"?><plist version="1.0"><array><string>x</string></array></plist>`} {
		if v := plistDoc([]byte(raw)); v != nil {
			t.Errorf("%s: want nil, got %v", name, v)
		}
	}
}

// The edge cases a hand-written converter gets wrong: an empty <string/> is "", not null; empty containers stay containers; numbers stay numbers.
func TestPlistDocEdges(t *testing.T) {
	v := plistDoc([]byte(`<?xml version="1.0"?><plist version="1.0"><dict>
	<key>Empty</key><string/><key>EmptyDict</key><dict/><key>EmptyArray</key><array/><key>N</key><integer>14</integer><key>Big</key><integer>9223372036854775807</integer><key>Neg</key><integer>-3</integer>
	</dict></plist>`))
	m, ok := v.(bson.M)
	if !ok {
		t.Fatalf("not a document: %T", v)
	}
	if s, isStr := m["Empty"].(string); !isStr || s != "" {
		t.Errorf("empty string: %#v", m["Empty"])
	}
	if d, isDoc := m["EmptyDict"].(bson.M); !isDoc || len(d) != 0 {
		t.Errorf("empty dict: %#v", m["EmptyDict"])
	}
	if a, isArr := m["EmptyArray"].(bson.A); !isArr || len(a) != 0 {
		t.Errorf("empty array: %#v", m["EmptyArray"])
	}
	if m["N"] != int64(14) || m["Big"] != int64(9223372036854775807) || m["Neg"] != int64(-3) {
		t.Errorf("integers: %#v %#v %#v", m["N"], m["Big"], m["Neg"])
	}
}
