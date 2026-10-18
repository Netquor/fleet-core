package enroll

import (
	"strings"
	"testing"

	"github.com/micromdm/plist"
)

func parse(t *testing.T, b []byte) []map[string]any {
	var p struct{ PayloadContent []map[string]any }
	if err := plist.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return p.PayloadContent
}

func TestACMEProfile(t *testing.T) {
	o := Options{Organization: "Example", Identifier: "com.example.enroll", ServerURL: "https://mdm.example.com/mdm", SCEPURL: "https://mdm.example.com/scep", Topic: "com.apple.mgmt.External.x", ACMEDirectoryURL: "https://mdm.example.com/acme/directory"}
	b, err := Build(o, "ignored-challenge")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ignored-challenge") || strings.Contains(string(b), "com.apple.security.scep") {
		t.Error("an ACME profile carries no SCEP challenge")
	}
	var acme, mdm map[string]any
	for _, p := range parse(t, b) {
		switch p["PayloadType"] {
		case "com.apple.security.acme":
			acme = p
		case "com.apple.mdm":
			mdm = p
		}
	}
	if acme == nil || acme["DirectoryURL"] != "https://mdm.example.com/acme/directory" || acme["Attest"] != true || acme["HardwareBound"] != true || acme["KeyType"] != "ECSECPrimeRandom" || acme["ClientIdentifier"] == "" {
		t.Fatalf("acme payload: %v", acme)
	}
	if mdm["IdentityCertificateUUID"] != acme["PayloadUUID"] {
		t.Errorf("the MDM payload points at %v, the identity is %v", mdm["IdentityCertificateUUID"], acme["PayloadUUID"])
	}
}

func TestBYODProfile(t *testing.T) {
	o := Options{Organization: "Example", Identifier: "com.example.byod", ServerURL: "https://mdm.example.com/mdm", SCEPURL: "https://mdm.example.com/scep", Topic: "com.apple.mgmt.External.x"}
	if _, err := Build(Options{Organization: o.Organization, Identifier: o.Identifier, ServerURL: o.ServerURL, SCEPURL: o.SCEPURL, Topic: o.Topic, BYOD: true}, "c"); err == nil {
		t.Error("a User Enrollment profile without a person was built")
	}
	o.BYOD, o.ManagedAppleID, o.SubjectCN = true, "alice@example.com", "ue-123"
	b, err := Build(o, "c")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range parse(t, b) {
		if p["PayloadType"] == "com.apple.mdm" {
			if p["EnrollmentMode"] != "BYOD" || p["AssignedManagedAppleID"] != "alice@example.com" || p["AccessRights"] != nil {
				t.Errorf("%v", p)
			}
		}
	}
}
