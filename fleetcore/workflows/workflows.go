// Package workflows is what an administrator does to one device that takes more than sending a command: turn on Lost Mode and find the device, rotate its FileVault recovery key and keep the
// new one, set a recovery lock, fetch an Activation Lock bypass code. Each sends the right command for the device's platform and enrollment (the schema decides what exists and what is
// allowed), waits for the answer, and files what comes back where it can be read only with a recorded reason.
package workflows

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanomdm/fleetcore/blueprints"
	"github.com/micromdm/nanomdm/fleetcore/commands"
	"github.com/micromdm/nanomdm/fleetcore/seal"
	"github.com/micromdm/nanomdm/fleetcore/vault"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Service runs the workflows.
type Service struct {
	Devices *blueprints.Store
	Enq     blueprints.Enqueuer
	Vault   *vault.Store
	Logger  log.Logger
	Now     func() time.Time
	// Sealer protects what a workflow keeps while it waits for an answer (the private key of a FileVault rotation).
	Sealer seal.Interface

	db  *mongo.Database
	tid string
}

// New returns the service. tenant may be empty.
func New(ctx context.Context, db *mongo.Database, tenant string, devices *blueprints.Store, enq blueprints.Enqueuer, v *vault.Store, logger log.Logger) (*Service, error) {
	if logger == nil {
		logger = log.NopLogger
	}
	s := &Service{Devices: devices, Enq: enq, Vault: v, Logger: logger, db: db, tid: tenant}
	k := bson.D{{Key: "command_uuid", Value: 1}}
	if tenant != "" {
		k = bson.D{{Key: "t", Value: 1}, {Key: "command_uuid", Value: 1}}
	}
	if _, err := db.Collection("wf_commands").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: k},
		{Keys: bson.D{{Key: "created_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(30 * 24 * 3600)},
	}); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Service) key(parts ...string) string {
	k := strings.Join(parts, "\x1f")
	if s.tid == "" {
		return k
	}
	return s.tid + "\x1f" + k
}

func (s *Service) scope(f bson.D) bson.D {
	if s.tid == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, f...)
}

func (s *Service) stamp(d bson.D) bson.D {
	if s.tid == "" {
		return d
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, d...)
}

// ErrUnavailable means the device cannot do this (its platform, OS or enrollment does not have the command).
type ErrUnavailable struct{ Why string }

func (e ErrUnavailable) Error() string { return e.Why }

type tracked struct {
	Workflow string `bson:"workflow"`
	Device   string `bson:"device"`
	By       string `bson:"by"`
	Extra    string `bson:"extra"`
	Meta     bson.M `bson:"meta"`
}

// send builds a command for the device, queues it and remembers what it was for.
func (s *Service) send(ctx context.Context, d *blueprints.Device, workflow, by, requestType string, params map[string]any, extra []byte, meta bson.M) (string, error) {
	cmd, ok := commands.Default().Get(requestType)
	if !ok {
		return "", ErrUnavailable{requestType + " is not a command in the schema in use"}
	}
	body, uuid, ps := commands.Build(cmd, params, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion, UserEnrollment: d.UserEnrollment()})
	if len(ps) > 0 {
		return "", ErrUnavailable{ps[0].Error()}
	}
	if info, ok := cmd.OS[schemasOS(d.Platform)]; ok && info.Supervised && (d.Supervised == nil || !*d.Supervised) {
		return "", ErrUnavailable{requestType + " needs a supervised " + d.Platform + " device"}
	}
	enc := ""
	if len(extra) > 0 {
		var err error
		if enc, err = seal.Put(s.Sealer, "workflow.extra", []byte(base64.StdEncoding.EncodeToString(extra))); err != nil {
			return "", err
		}
	}
	doc := s.stamp(bson.D{{Key: "_id", Value: s.key(uuid)}, {Key: "command_uuid", Value: uuid}, {Key: "workflow", Value: workflow}, {Key: "device", Value: d.ID}, {Key: "by", Value: by}, {Key: "extra", Value: enc}, {Key: "meta", Value: meta}, {Key: "created_at", Value: s.now()}})
	if _, err := s.db.Collection("wf_commands").InsertOne(ctx, doc); err != nil {
		return "", err
	}
	if err := s.Enq.Enqueue(ctx, []string{d.ID}, body); err != nil {
		return "", fmt.Errorf("queueing %s: %w", requestType, err)
	}
	return uuid, nil
}

func schemasOS(platform string) string {
	if platform == "iPadOS" {
		return "iOS"
	}
	return platform
}

func (s *Service) device(ctx context.Context, id string) (*blueprints.Device, error) {
	return s.Devices.GetDevice(ctx, id)
}

// ---- installed apps ----

// RefreshApps asks the device what is installed (only what the organization manages, on a User Enrollment, which is all it may see).
func (s *Service) RefreshApps(ctx context.Context, device, by string) (string, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return "", err
	}
	params := map[string]any{}
	if d.UserEnrollment() {
		params["ManagedAppsOnly"] = true
	}
	return s.send(ctx, d, "apps", by, "InstalledApplicationList", params, nil, nil)
}

// ---- Lost Mode ----

// LostModeRequest is what the person finding the device is told.
type LostModeRequest struct {
	Message  string `json:"message"`
	Phone    string `json:"phone"`
	Footnote string `json:"footnote"`
}

// EnableLostMode locks a supervised iPhone or iPad with a message and a number to call.
func (s *Service) EnableLostMode(ctx context.Context, device, by string, r LostModeRequest) (string, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return "", err
	}
	if r.Message == "" && r.Phone == "" {
		return "", errors.New("Lost Mode needs a message or a phone number to show")
	}
	params := map[string]any{}
	for k, v := range map[string]string{"Message": r.Message, "PhoneNumber": r.Phone, "Footnote": r.Footnote} {
		if v != "" {
			params[k] = v
		}
	}
	return s.send(ctx, d, "lost-mode-enable", by, "EnableLostMode", params, nil, bson.M{"message": r.Message, "phone": r.Phone, "footnote": r.Footnote})
}

// DisableLostMode ends it.
func (s *Service) DisableLostMode(ctx context.Context, device, by string) (string, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return "", err
	}
	return s.send(ctx, d, "lost-mode-disable", by, "DisableLostMode", map[string]any{}, nil, nil)
}

// Locate asks a device in Lost Mode where it is.
func (s *Service) Locate(ctx context.Context, device, by string) (string, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return "", err
	}
	if d.LostMode == nil || !d.LostMode.Enabled {
		return "", ErrUnavailable{"a device can be located only while it is in Lost Mode"}
	}
	return s.send(ctx, d, "locate", by, "DeviceLocation", map[string]any{}, nil, nil)
}

// PlaySound makes a device in Lost Mode play a sound.
func (s *Service) PlaySound(ctx context.Context, device, by string) (string, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return "", err
	}
	if d.LostMode == nil || !d.LostMode.Enabled {
		return "", ErrUnavailable{"the sound plays only while the device is in Lost Mode"}
	}
	return s.send(ctx, d, "play-sound", by, "PlayLostModeSound", map[string]any{}, nil, nil)
}

// ---- Activation Lock ----

// RequestBypassCode asks a supervised device for the code that lets it be reactivated without its owner's Apple Account.
func (s *Service) RequestBypassCode(ctx context.Context, device, by string) (string, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return "", err
	}
	return s.send(ctx, d, "activation-lock-bypass", by, "ActivationLockBypassCode", map[string]any{}, nil, nil)
}

// ClearBypassCode removes the code from the device.
func (s *Service) ClearBypassCode(ctx context.Context, device, by string) (string, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return "", err
	}
	return s.send(ctx, d, "activation-lock-bypass-clear", by, "ClearActivationLockBypassCode", map[string]any{}, nil, nil)
}

// ---- FileVault ----

// RotateFileVault makes the Mac produce a new personal recovery key and encrypt it to a one-time certificate only this server can open. password unlocks FileVault; empty uses the key now
// in the vault (the previous recovery key is accepted as the password).
func (s *Service) RotateFileVault(ctx context.Context, device, by, password string) (string, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return "", err
	}
	if password == "" {
		prev, ok, err := s.Vault.Peek(ctx, device, vault.FileVaultRecoveryKey)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("no recovery key is stored for this Mac: give a password that can unlock FileVault")
		}
		password = prev
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "fleetcore FileVault escrow"}, NotBefore: s.now().Add(-time.Hour), NotAfter: s.now().Add(48 * time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	params := map[string]any{
		"KeyType":                    "personal",
		"FileVaultUnlock":            map[string]any{"Password": password},
		"ReplyEncryptionCertificate": base64.StdEncoding.EncodeToString(der),
	}
	return s.send(ctx, d, "filevault-rotate", by, "RotateFileVaultKey", params, x509.MarshalPKCS1PrivateKey(key), bson.M{"cert": base64.StdEncoding.EncodeToString(der)})
}

// ---- recovery lock and firmware password ----

// SetRecoveryLock sets, changes or (with an empty new password) clears the recovery lock of an Apple silicon Mac. The server makes the password unless one is given, and keeps it.
func (s *Service) SetRecoveryLock(ctx context.Context, device, by, newPassword string, clear bool) (string, error) {
	return s.lockPassword(ctx, device, by, newPassword, clear, "recovery-lock", "SetRecoveryLock", vault.RecoveryLock)
}

// SetFirmwarePassword does the same for an Intel Mac's firmware password.
func (s *Service) SetFirmwarePassword(ctx context.Context, device, by, newPassword string, clear bool) (string, error) {
	return s.lockPassword(ctx, device, by, newPassword, clear, "firmware-password", "SetFirmwarePassword", vault.FirmwarePassword)
}

func (s *Service) lockPassword(ctx context.Context, device, by, newPassword string, clear bool, workflow, command, kind string) (string, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return "", err
	}
	params := map[string]any{}
	if cur, ok, err := s.Vault.Peek(ctx, device, kind); err != nil {
		return "", err
	} else if ok && cur != "" {
		params["CurrentPassword"] = cur
	}
	switch {
	case clear:
		params["NewPassword"] = ""
	case newPassword != "":
		params["NewPassword"] = newPassword
	default:
		if params["NewPassword"], err = vault.Password(16); err != nil {
			return "", err
		}
	}
	// the new password is kept (sealed) with the command, so it is stored only when the device accepts it
	pw := params["NewPassword"].(string)
	return s.send(ctx, d, workflow, by, command, params, []byte(pw), bson.M{"clear": clear})
}

// ---- results ----

// HandleResult is called with every command result; it finishes the workflow the command belonged to. Connect it to blueprints.Observer.OnResult.
func (s *Service) HandleResult(ctx context.Context, device string, res *mdm.CommandResults) {
	var t tracked
	if err := s.db.Collection("wf_commands").FindOne(ctx, bson.D{{Key: "_id", Value: s.key(res.CommandUUID)}}).Decode(&t); err != nil {
		return // not one of ours
	}
	if t.Device != device {
		return
	}
	if res.Status != "Acknowledged" {
		if res.Status == "Error" || res.Status == "CommandFormatError" {
			s.Logger.Info("msg", "workflow command failed", "workflow", t.Workflow, "device", device, "status", res.Status)
		}
		return
	}
	var err error
	switch t.Workflow {
	case "apps":
		var r struct {
			InstalledApplicationList []struct {
				Identifier   string
				Name         string
				Version      string
				ShortVersion string
				IsManaged    bool
			}
		}
		if err = plist.Unmarshal(res.Raw, &r); err == nil {
			apps := make([]blueprints.AppInfo, 0, len(r.InstalledApplicationList))
			for _, a := range r.InstalledApplicationList {
				apps = append(apps, blueprints.AppInfo{Identifier: a.Identifier, Name: a.Name, Version: a.Version, ShortVersion: a.ShortVersion, Managed: a.IsManaged})
			}
			err = s.Devices.SetDeviceFields(ctx, device, bson.D{{Key: "apps", Value: apps}, {Key: "apps_at", Value: s.now()}}, false)
		}
	case "lost-mode-enable":
		msg, _ := t.Meta["message"].(string)
		phone, _ := t.Meta["phone"].(string)
		foot, _ := t.Meta["footnote"].(string)
		err = s.Devices.SetDeviceFields(ctx, device, bson.D{{Key: "lost_mode", Value: blueprints.LostMode{Enabled: true, Message: msg, Phone: phone, Footnote: foot, Confirmed: true, Since: s.now()}}}, false)
	case "lost-mode-disable":
		err = s.Devices.SetDeviceFields(ctx, device, bson.D{{Key: "lost_mode", Value: blueprints.LostMode{Enabled: false, Confirmed: true, Since: s.now()}}}, false)
	case "locate":
		var r struct {
			Latitude, Longitude, Altitude, HorizontalAccuracy float64
		}
		if err = plist.Unmarshal(res.Raw, &r); err == nil {
			err = s.Devices.SetDeviceFields(ctx, device, bson.D{{Key: "location", Value: blueprints.Location{Latitude: r.Latitude, Longitude: r.Longitude, Altitude: r.Altitude, HorizontalAccuracy: r.HorizontalAccuracy, At: s.now()}}}, false)
		}
	case "activation-lock-bypass":
		var r struct{ ActivationLockBypassCode string }
		if err = plist.Unmarshal(res.Raw, &r); err == nil && r.ActivationLockBypassCode != "" {
			_, err = s.Vault.Put(ctx, device, vault.ActivationLockBypass, r.ActivationLockBypassCode, t.By)
		}
	case "filevault-rotate":
		err = s.finishFileVault(ctx, device, &t, res.Raw)
	case "recovery-lock", "firmware-password":
		kind := vault.RecoveryLock
		if t.Workflow == "firmware-password" {
			kind = vault.FirmwarePassword
		}
		var pw []byte
		if pw, err = s.unpack(t.Extra); err == nil {
			cleared, _ := t.Meta["clear"].(bool)
			if cleared {
				pw = []byte{}
			}
			_, err = s.Vault.Put(ctx, device, kind, string(pw), t.By)
		}
	}
	if err != nil {
		s.Logger.Info("msg", "finishing a workflow", "workflow", t.Workflow, "device", device, "err", err)
	}
}

func (s *Service) finishFileVault(ctx context.Context, device string, t *tracked, raw []byte) error {
	var r struct {
		RotateResult            string
		EncryptedNewRecoveryKey []byte
	}
	if err := plist.Unmarshal(raw, &r); err != nil {
		return err
	}
	if len(r.EncryptedNewRecoveryKey) == 0 {
		return fmt.Errorf("the Mac sent no new recovery key (%s)", r.RotateResult)
	}
	privDER, err := s.unpack(t.Extra)
	if err != nil {
		return err
	}
	key, err := x509.ParsePKCS1PrivateKey(privDER)
	if err != nil {
		return err
	}
	certB64, _ := t.Meta["cert"].(string)
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	p7, err := pkcs7.Parse(r.EncryptedNewRecoveryKey)
	if err != nil {
		return fmt.Errorf("the new recovery key is not a CMS message: %w", err)
	}
	plain, err := p7.Decrypt(cert, key)
	if err != nil {
		return fmt.Errorf("the new recovery key does not open with the one-time key: %w", err)
	}
	_, err = s.Vault.Put(ctx, device, vault.FileVaultRecoveryKey, strings.TrimSpace(string(plain)), t.By)
	return err
}

// unpack reads what send kept with the command.
func (s *Service) unpack(stored string) ([]byte, error) {
	b, err := seal.Get(s.Sealer, "workflow.extra", stored)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(string(b))
}
