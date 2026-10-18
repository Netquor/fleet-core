package dep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/micromdm/nanodep/godep"
)

// KnownSetupPanes are the Setup Assistant panes a DEP profile can skip. Apple adds panes with each release; one not in this list is passed through and reported, not refused.
var KnownSetupPanes = []string{
	"Accessibility", "Android", "Appearance", "AppleID", "AppStore", "Biometric", "CameraButton", "DeviceToDeviceMigration", "Diagnostics", "DisplayTone", "EnableLockdownMode", "FileVault",
	"HomeButtonSensitivity", "iCloudDiagnostics", "iCloudStorage", "iMessageAndFaceTime", "Intelligence", "Location", "MessagingActivationUsingPhoneNumber", "OnBoarding", "Passcode", "Payment",
	"Privacy", "Registration", "Restore", "RestoreCompleted", "ScreenSaver", "ScreenTime", "SIMSetup", "Safety", "Siri", "SoftwareUpdate", "TapToSetup", "TermsOfAddress", "TOS", "UpdateCompleted",
	"Wallpaper", "WatchMigration", "Welcome", "Zoom", "ActionButton", "Appearance", "TVHomeScreenSync", "TVProviderSignIn", "TVRoom", "Tips", "Keyboard", "Multitasking", "Display", "SpokenLanguage",
}

// ProfileSpec is a DEP profile: how a device assigned to this server behaves in Setup Assistant. Zero values take safe defaults for a managed fleet: supervised, the profile mandatory,
// the person unable to remove management, and the device held in Setup Assistant (await configuration) until the server says it is configured.
type ProfileSpec struct {
	Name string `json:"name"`
	// URL is where the device fetches its enrollment profile (default: this server's /enroll/ade).
	URL string `json:"url,omitempty"`
	// Supervised, Mandatory, Removable and AwaitConfigured default to true, true, false and true.
	Supervised      *bool `json:"supervised,omitempty"`
	Mandatory       *bool `json:"mandatory,omitempty"`
	Removable       *bool `json:"removable,omitempty"`
	AwaitConfigured *bool `json:"await_configured,omitempty"`
	AllowPairing    bool  `json:"allow_pairing,omitempty"`
	AutoAdvance     bool  `json:"auto_advance,omitempty"`
	MultiUser       bool  `json:"multi_user,omitempty"`
	// SkipSetupItems are panes to skip (see KnownSetupPanes).
	SkipSetupItems []string `json:"skip_setup_items,omitempty"`
	Department     string   `json:"department,omitempty"`
	SupportPhone   string   `json:"support_phone,omitempty"`
	SupportEmail   string   `json:"support_email,omitempty"`
	OrgMagic       string   `json:"org_magic,omitempty"`
	// Assign makes it the profile new devices get; AssignExisting also assigns it to the devices already known.
	Assign         bool `json:"assign,omitempty"`
	AssignExisting bool `json:"assign_existing,omitempty"`
}

// DefineResult is what defining a profile did.
type DefineResult struct {
	ProfileUUID  string   `json:"profile_uuid"`
	UnknownPanes []string `json:"unknown_panes,omitempty"`
	Assigned     int      `json:"assigned,omitempty"`
	NotAssigned  []string `json:"not_assigned,omitempty"`
}

func def(p *bool, d bool) bool {
	if p == nil {
		return d
	}
	return *p
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Profile makes the DEP profile for the DEP name's device assignments.
func (s *Service) DefineProfile(ctx context.Context, name string, spec ProfileSpec) (*DefineResult, error) {
	if spec.Name == "" {
		return nil, errors.New("the profile needs a name")
	}
	url := spec.URL
	if url == "" {
		url = s.EnrollURL
	}
	if url == "" {
		return nil, errors.New("no enrollment URL: give url, or run the server with its public address")
	}
	known := map[string]bool{}
	for _, k := range KnownSetupPanes {
		known[k] = true
	}
	res := &DefineResult{}
	for _, p := range spec.SkipSetupItems {
		if !known[p] {
			res.UnknownPanes = append(res.UnknownPanes, p)
		}
	}
	b := func(v bool) *bool { return &v }
	p := &godep.ProfileJson{
		ProfileName:           &spec.Name,
		Url:                   &url,
		IsSupervised:          b(def(spec.Supervised, true)),
		IsMandatory:           b(def(spec.Mandatory, true)),
		IsMdmRemovable:        def(spec.Removable, false),
		AwaitDeviceConfigured: b(def(spec.AwaitConfigured, true)),
		AllowPairing:          spec.AllowPairing,
		AutoAdvanceSetup:      b(spec.AutoAdvance),
		IsMultiUser:           b(spec.MultiUser),
		SkipSetupItems:        spec.SkipSetupItems,
		Department:            strp(spec.Department),
		SupportPhoneNumber:    strp(spec.SupportPhone),
		SupportEmailAddress:   strp(spec.SupportEmail),
		OrgMagic:              spec.OrgMagic,
	}
	out, err := s.client.DefineProfile(ctx, name, p)
	if err != nil {
		return nil, fmt.Errorf("defining the profile: %w", err)
	}
	if out.ProfileUuid == nil || *out.ProfileUuid == "" {
		return nil, errors.New("Apple did not return a profile UUID")
	}
	res.ProfileUUID = *out.ProfileUuid
	if err := s.setProfileFacts(ctx, name, res.ProfileUUID, def(spec.Supervised, true), def(spec.AwaitConfigured, true)); err != nil {
		return nil, err
	}
	if spec.Assign || spec.AssignExisting {
		if err := s.Store.StoreAssignerProfile(ctx, name, res.ProfileUUID); err != nil {
			return nil, err
		}
	}
	if spec.AssignExisting {
		serials, err := s.serialsOf(ctx, name)
		if err != nil {
			return nil, err
		}
		for len(serials) > 0 {
			n := min(len(serials), 1000)
			r, err := s.client.AssignProfile(ctx, name, res.ProfileUUID, serials[:n]...)
			if err != nil {
				return res, fmt.Errorf("assigning: %w", err)
			}
			for serial, status := range r.Devices {
				if status == "SUCCESS" || string(status) == "SUCCESS" {
					res.Assigned++
				} else {
					res.NotAssigned = append(res.NotAssigned, serial)
				}
			}
			serials = serials[n:]
		}
		sort.Strings(res.NotAssigned)
	}
	return res, nil
}

func (s *Service) profileRoute(mux *http.ServeMux, prefix string) {
	mux.HandleFunc("POST "+prefix+"/profiles/{name}", func(w http.ResponseWriter, r *http.Request) {
		var spec ProfileSpec
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&spec); err != nil {
			http.Error(w, "the body is not valid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		res, err := s.DefineProfile(r.Context(), r.PathValue("name"), spec)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "result": res})
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	})
}
