package blueprints

import (
	"context"
	"strings"
	"time"

	"github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"
	"github.com/micromdm/plist"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Observer is a NanoMDM service that watches check-ins to keep the inventory current and to learn how commands the engine sent turned out. Add it beside the main service with
// service/multi: it never answers a device, so it cannot change the protocol.
type Observer struct {
	service.NopService
	Store *Store
	// DDM, if set, lets a user channel that checks out have its declarations cleared at once.
	DDM    *ddm.Store
	Logger log.Logger
	Now    func() time.Time
}

var _ service.CheckinAndCommandService = (*Observer)(nil)

func (o *Observer) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now().UTC()
}

func (o *Observer) logger() log.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return log.NopLogger
}

// PlatformOf names the platform from Apple's product name or model identifier (Mac15,6; iPhone16,1; iPad14,3; AppleTV11,1; RealityDevice14,1; Watch7,1).
func PlatformOf(product string) string {
	switch {
	case strings.HasPrefix(product, "Mac"), strings.HasPrefix(product, "iMac"), strings.HasPrefix(product, "MacBook"), strings.HasPrefix(product, "Macmini"), strings.HasPrefix(product, "VirtualMac"):
		return "macOS"
	case strings.HasPrefix(product, "iPhone"), strings.HasPrefix(product, "iPod"):
		return "iOS"
	case strings.HasPrefix(product, "iPad"):
		return "iPadOS"
	case strings.HasPrefix(product, "AppleTV"):
		return "tvOS"
	case strings.HasPrefix(product, "RealityDevice"):
		return "visionOS"
	case strings.HasPrefix(product, "Watch"):
		return "watchOS"
	}
	return ""
}

// userChannel reports whether the request is from a user channel of a device (its enrollment ID has a parent) and records it.
func (o *Observer) userChannel(r *mdm.Request) (bool, error) {
	if r.EnrollID == nil || r.ParentID == "" {
		return false, nil
	}
	return true, o.Store.AddUser(r.Context(), r.ParentID, r.ID)
}

func (o *Observer) Authenticate(r *mdm.Request, m *mdm.Authenticate) error {
	if ok, err := o.userChannel(r); ok {
		return err
	}
	var info struct {
		OSVersion   string
		ProductName string
		Model       string
		DeviceName  string
	}
	_ = plist.Unmarshal(m.Raw, &info)
	product := info.ProductName
	if product == "" {
		product = info.Model
	}
	return o.Store.UpsertDevice(r.Context(), DeviceUpdate{
		ID: r.ID, UDID: m.UDID, Serial: m.SerialNumber, Name: info.DeviceName, Platform: PlatformOf(product), Model: product, OSVersion: info.OSVersion, EnrollType: r.Type.String(),
	}, o.now())
}

func (o *Observer) TokenUpdate(r *mdm.Request, m *mdm.TokenUpdate) error {
	if ok, err := o.userChannel(r); ok {
		return err
	}
	// A device that enrolled before the observer was running (or whose inventory was lost) is created here, and every token update asks for a look.
	return o.Store.UpsertDevice(r.Context(), DeviceUpdate{ID: r.ID, UDID: m.UDID, EnrollType: r.Type.String()}, o.now())
}

func (o *Observer) CheckOut(r *mdm.Request, m *mdm.CheckOut) error {
	if r.EnrollID != nil && r.ParentID != "" {
		if o.DDM != nil {
			if _, _, err := o.DDM.Replace(r.Context(), r.ID, nil); err != nil {
				return err
			}
		}
		return o.Store.RemoveUser(r.Context(), r.ParentID, r.ID)
	}
	return o.Store.Deactivate(r.Context(), r.ID)
}

func (o *Observer) CommandAndReportResults(r *mdm.Request, res *mdm.CommandResults) (*mdm.Command, error) {
	if res == nil || res.CommandUUID == "" || res.Status == "Idle" {
		return nil, nil
	}
	ctx := r.Context()
	// DeviceInformation answers refresh the inventory.
	if res.Status == "Acknowledged" {
		var back struct {
			QueryResponses map[string]any
		}
		if err := plist.Unmarshal(res.Raw, &back); err == nil && len(back.QueryResponses) > 0 {
			if err := o.learn(ctx, r.ID, back.QueryResponses); err != nil {
				o.logger().Info("msg", "recording device information", "device", r.ID, "err", err)
			}
		}
	}
	a, err := o.Store.ApplicationByCommand(ctx, res.CommandUUID)
	if err != nil || a == nil || a.Device != r.ID {
		return nil, err
	}
	switch res.Status {
	case "Acknowledged":
		if a.State == StateRemoving {
			if err := o.Store.DeleteApplication(ctx, a.Device, a.Blueprint, a.Item); err != nil {
				return nil, err
			}
			// A profile moved to declarative delivery (or any removal) may have something waiting on it.
			return nil, o.Store.SetDeviceFields(ctx, a.Device, bson.D{}, true)
		}
		a.State, a.Error = StateApplied, ""
	case "Error", "CommandFormatError":
		msg := res.Status
		if len(res.ErrorChain) > 0 {
			e := res.ErrorChain[0]
			msg = e.USEnglishDescription
			if msg == "" {
				msg = e.LocalizedDescription
			}
			if msg == "" {
				msg = e.ErrorDomain
			}
		}
		if a.State == StateRemoving {
			// Removing something that is not there is the state we wanted.
			return nil, o.Store.DeleteApplication(ctx, a.Device, a.Blueprint, a.Item)
		}
		a.State, a.Error = StateFailed, msg
		a.Attempts++
		// Look at the device again when the retry is due.
		_ = o.Store.SetDeviceFields(ctx, a.Device, bson.D{{Key: "reconcile_at", Value: o.now().Add(5 * time.Minute << uint(min(a.Attempts, 5)))}}, false)
	default:
		return nil, nil // NotNow and the like: still waiting
	}
	return nil, o.Store.PutApplication(ctx, *a)
}

// learn updates the inventory from DeviceInformation answers; a changed OS version makes the device due, because what applies may have changed.
func (o *Observer) learn(ctx context.Context, id string, q map[string]any) error {
	s := func(k string) string { v, _ := q[k].(string); return v }
	fields := bson.D{{Key: "os_checked_at", Value: o.now()}}
	touch := false
	if v := s("OSVersion"); v != "" {
		if old, err := o.Store.GetDevice(ctx, id); err == nil && old.OSVersion != v {
			touch = true
		}
		fields = append(fields, bson.E{Key: "os_version", Value: v})
		if n, ok := versionNum(v); ok {
			fields = append(fields, bson.E{Key: "os_num", Value: n})
		}
	}
	if sup, ok := q["IsSupervised"].(bool); ok {
		fields = append(fields, bson.E{Key: "supervised", Value: sup})
		if old, err := o.Store.GetDevice(ctx, id); err == nil && (old.Supervised == nil || *old.Supervised != sup) {
			touch = true // what a device may receive depends on it
		}
	}
	for k, f := range map[string]string{"DeviceName": "name", "SerialNumber": "serial"} {
		if v := s(k); v != "" {
			fields = append(fields, bson.E{Key: f, Value: v})
		}
	}
	if p := PlatformOf(firstNonEmpty(s("ProductName"), s("Model"))); p != "" {
		fields = append(fields, bson.E{Key: "platform", Value: p}, bson.E{Key: "model", Value: firstNonEmpty(s("ProductName"), s("Model"))})
	}
	return o.Store.SetDeviceFields(ctx, id, fields, touch)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
