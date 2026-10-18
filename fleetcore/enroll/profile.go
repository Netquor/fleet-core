// Package enroll builds the enrollment profile a device installs to enroll in a fleetcore server: a SCEP payload that gets the device its identity certificate, and an MDM payload that
// points it at the server. fleetcore serves it itself (no separate web service), with a fresh one-use SCEP challenge in every copy.
package enroll

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"

	"github.com/micromdm/plist"
)

// Options describe the profile.
type Options struct {
	Organization string
	// Identifier is the profile's PayloadIdentifier (reverse-DNS), for example "com.example.mdm.enroll".
	Identifier string
	// ServerURL is where devices send MDM commands and check-ins (https://host/mdm).
	ServerURL string
	// CheckInURL is a separate check-in endpoint (https://host/checkin); empty to use ServerURL for both.
	CheckInURL string
	// SCEPURL is where the device asks for its identity (https://host/scep).
	SCEPURL string
	// Topic is the APNs topic of the push certificate (com.apple.mgmt.External.<uuid>).
	Topic string
	// SignMessage makes the device sign every request (Mdm-Signature header); use it when TLS is terminated in front of the server and the client certificate does not reach it.
	SignMessage bool
	// RemovalDisallowed stops the person removing the profile on a supervised device.
	RemovalDisallowed bool
	// BYOD makes a User Enrollment profile (account-driven enrollment of a personal device): the organization manages only its own data. ManagedAppleID is the person's Managed Apple
	// Account and SubjectCN the name the device's identity certificate carries (a UDID is not available on User Enrollment).
	BYOD           bool
	ManagedAppleID string
	SubjectCN      string
}

// Build returns the profile as an XML property list, with the SCEP challenge in it.
func Build(o Options, challenge string) ([]byte, error) {
	if o.Identifier == "" || o.ServerURL == "" || o.SCEPURL == "" || o.Topic == "" {
		return nil, fmt.Errorf("an enrollment profile needs an identifier, a server URL, a SCEP URL and a push topic")
	}
	org := o.Organization
	if org == "" {
		org = "Device Management"
	}
	scepUUID := uuid()
	cn := "%HardwareUUID%"
	if o.SubjectCN != "" {
		cn = o.SubjectCN
	}
	mdm := map[string]interface{}{
		"PayloadType":             "com.apple.mdm",
		"PayloadVersion":          1,
		"PayloadIdentifier":       o.Identifier + ".mdm",
		"PayloadUUID":             uuid(),
		"PayloadDisplayName":      "Device management",
		"AccessRights":            8191,
		"CheckOutWhenRemoved":     true,
		"IdentityCertificateUUID": scepUUID,
		"ServerURL":               o.ServerURL,
		"SignMessage":             o.SignMessage,
		"Topic":                   o.Topic,
		"ServerCapabilities":      []string{"com.apple.mdm.per-user-connections", "com.apple.mdm.bootstraptoken", "com.apple.mdm.token"},
	}
	if o.CheckInURL != "" {
		mdm["CheckInURL"] = o.CheckInURL
	}
	if o.BYOD {
		if o.ManagedAppleID == "" || o.SubjectCN == "" {
			return nil, fmt.Errorf("a User Enrollment profile needs the person's Managed Apple Account and a name for the identity certificate")
		}
		delete(mdm, "AccessRights") // User Enrollment grants no rights over the device
		mdm["EnrollmentMode"] = "BYOD"
		mdm["AssignedManagedAppleID"] = o.ManagedAppleID
	}
	scep := map[string]interface{}{
		"PayloadType":        "com.apple.security.scep",
		"PayloadVersion":     1,
		"PayloadIdentifier":  o.Identifier + ".scep",
		"PayloadUUID":        scepUUID,
		"PayloadDisplayName": "Device identity",
		"PayloadContent": map[string]interface{}{
			"URL":        o.SCEPURL,
			"Name":       "Device Management Identity",
			"Subject":    [][][]string{{{"O", org}}, {{"CN", cn}}},
			"Challenge":  challenge,
			"Key Type":   "RSA",
			"Keysize":    2048,
			"Key Usage":  5, // signing and encryption
			"Retries":    3,
			"RetryDelay": 10,
		},
	}
	root := map[string]interface{}{
		"PayloadType":         "Configuration",
		"PayloadVersion":      1,
		"PayloadIdentifier":   o.Identifier,
		"PayloadUUID":         uuid(),
		"PayloadDisplayName":  org + " Device Management",
		"PayloadDescription":  "Enrolls this device in " + org + " device management.",
		"PayloadOrganization": org,
		"PayloadContent":      []interface{}{scep, mdm},
	}
	if o.RemovalDisallowed {
		root["PayloadRemovalDisallowed"] = true
	}
	return plist.MarshalIndent(root, "  ")
}

// ChallengeSource makes one-use challenge passwords (the CA's challenge store).
type ChallengeSource interface {
	SCEPChallenge() (string, error)
}

// Handler serves the profile. Every request makes a new one-use challenge, so the link can be shared without sharing a standing secret; put the access policy in front of it (a code, an invite)
// as the deployment needs.
func Handler(o Options, challenges ChallengeSource, authorize func(*http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if authorize != nil {
			if err := authorize(r); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		}
		pw, err := challenges.SCEPChallenge()
		if err != nil {
			http.Error(w, "could not make a challenge", http.StatusInternalServerError)
			return
		}
		body, err := Build(o, pw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="enroll.mobileconfig"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	})
}

func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]))
}
