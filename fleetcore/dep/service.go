package dep

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/micromdm/nanodep/cryptoutil"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/micromdm/nanodep/client"
	"github.com/micromdm/nanodep/godep"
	dephttp "github.com/micromdm/nanodep/http"
	"github.com/micromdm/nanodep/http/api"
	"github.com/micromdm/nanodep/http/apinext"
	"github.com/micromdm/nanodep/proxy"
	depstorage "github.com/micromdm/nanodep/storage"
	depsync "github.com/micromdm/nanodep/sync"
	"github.com/micromdm/nanolib/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const devicesCollection = "dep_devices"

// Service is ADE inside the server: the DEP API (tokens, config, token exchange, assigner profile, proxy to Apple's DEP API) and the syncers that keep the list of assigned devices current.
type Service struct {
	Store  *Store
	logger log.Logger
	client *godep.Client
	db     *mongo.Database
	tid    string

	// EnrollURL is the default URL in DEP profiles (this server's /enroll/ade).
	EnrollURL string
	// Interval between syncs of one DEP name (default 30 minutes).
	Interval time.Duration
	// OnDevices, if set, is called after each sync or fetch response (after devices are recorded).
	OnDevices func(ctx context.Context, depName string, isFetch bool, resp *godep.FetchDeviceResponseJson)

	mu      sync.Mutex
	ctx     context.Context
	running map[string]context.CancelFunc
	nows    map[string]chan struct{}
}

// NewService returns the service on store. tenant is the tenant recorded on device documents (empty when the database is one tenant's).
func NewService(ctx context.Context, db *mongo.Database, store *Store, tenant string, logger log.Logger) (*Service, error) {
	if logger == nil {
		logger = log.NopLogger
	}
	if _, err := db.Collection(devicesCollection).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "t", Value: 1}, {Key: "dep", Value: 1}, {Key: "serial", Value: 1}}}); err != nil {
		return nil, err
	}
	return &Service{Store: store, logger: logger, client: godep.NewClient(store), db: db, tid: tenant, Interval: 30 * time.Minute, running: map[string]context.CancelFunc{}, nows: map[string]chan struct{}{}}, nil
}

// Handler serves the DEP API under prefix (for example /v1/dep). Authentication is the caller's: wrap it.
//
//	PUT/GET  {prefix}/tokens/{name}      OAuth tokens (from the ABM server token, after the exchange)
//	PUT/GET  {prefix}/config/{name}      DEP API base URL and similar
//	GET/PUT  {prefix}/tokenpki/{name}    GET makes a certificate to upload to ABM; PUT decrypts the downloaded server token and stores the tokens
//	GET/PUT  {prefix}/assigner/{name}    the profile UUID applied to new devices
//	GET      {prefix}/names              DEP names
//	GET      {prefix}/devices/{name}     devices the syncer has recorded
//	POST     {prefix}/sync/{name}        sync now
//	ANY      {prefix}/proxy/{name}/...   Apple's DEP API with this name's credentials (define a profile, assign, disown)
func (s *Service) Handler(prefix string) http.Handler {
	mux := http.NewServeMux()
	strip := func(sub string, h http.Handler) {
		mux.Handle(prefix+sub, http.StripPrefix(prefix+sub, h))
	}
	l := s.logger
	tokens := dephttp.NewMethodMux()
	tokens.Handle("PUT", s.afterTokens(api.StoreAuthTokensHandler(s.Store, l.With("handler", "dep-store-tokens"))))
	// GET says whether tokens are stored and when they expire; the secrets are never returned.
	tokens.Handle("GET", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path
		t, err := s.Store.RetrieveAuthTokens(r.Context(), name)
		if err != nil {
			if errors.Is(err, depstorage.ErrNotFound) {
				http.Error(w, "no tokens are stored for that DEP name", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		key := t.ConsumerKey
		if len(key) > 4 {
			key = "…" + key[len(key)-4:]
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "stored": true, "consumer_key_suffix": key, "access_token_expiry": t.AccessTokenExpiry})
	}))
	strip("/tokens/", tokens)

	config := dephttp.NewMethodMux()
	config.Handle("GET", s.unlessMissing(func(ctx context.Context, name string) error {
		c, err := s.Store.RetrieveConfig(ctx, name)
		if err == nil && c == nil {
			return depstorage.ErrNotFound
		}
		return err
	}, api.RetrieveConfigHandler(s.Store, l.With("handler", "dep-get-config"))))
	config.Handle("PUT", api.StoreConfigHandler(s.Store, l.With("handler", "dep-store-config")))
	strip("/config/", config)

	pkiMux := dephttp.NewMethodMux()
	pkiMux.Handle("GET", api.GetCertTokenPKIHandler(s.Store, l.With("handler", "dep-get-token-pki")))
	pkiMux.Handle("PUT", s.afterTokens(api.DecryptTokenPKIHandler(s.Store, s.Store, l.With("handler", "dep-put-token-pki"))))
	strip("/tokenpki/", pkiMux)

	assigner := dephttp.NewMethodMux()
	assigner.Handle("GET", s.unlessMissing(func(ctx context.Context, name string) error {
		uuid, _, err := s.Store.RetrieveAssignerProfile(ctx, name)
		if err == nil && uuid == "" {
			return depstorage.ErrNotFound
		}
		return err
	}, api.RetrieveAssignerProfileHandler(s.Store, l.With("handler", "dep-get-assigner"))))
	assigner.Handle("PUT", api.StoreAssignerProfileHandler(s.Store, l.With("handler", "dep-store-assigner")))
	strip("/assigner/", assigner)

	names := dephttp.NewMethodMux()
	names.Handle("GET", apinext.NewQueryDEPNamesHandler(s.Store, l.With("handler", "dep-names")))
	strip("/names", names)

	s.profileRoute(mux, prefix)
	mux.HandleFunc(prefix+"/devices/", s.devicesHandler(prefix+"/devices/"))
	mux.HandleFunc(prefix+"/sync/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Path[len(prefix+"/sync/"):]
		if !s.SyncNow(name) {
			http.Error(w, "no syncer is running for that DEP name (store its tokens first)", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})

	p := proxy.New(client.NewTransport(http.DefaultTransport, http.DefaultClient, s.Store, nil), s.Store, l.With("component", "dep-proxy"))
	var ph http.Handler = proxy.ProxyDEPNameHandler(p, l.With("handler", "dep-proxy"))
	ph = http.StripPrefix(prefix+"/proxy/", ph)
	ph = delHeader(ph, "Authorization")
	mux.Handle(prefix+"/proxy/", ph)
	return mux
}

// unlessMissing answers 404 when the stored thing is not there; NanoDEP's own handlers answer 500 for that.
func (s *Service) unlessMissing(probe func(ctx context.Context, name string) error, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := probe(r.Context(), r.URL.Path); errors.Is(err, depstorage.ErrNotFound) {
			http.Error(w, "nothing is stored for that DEP name", http.StatusNotFound)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func delHeader(h http.Handler, header string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.Header.Del(header); h.ServeHTTP(w, r) })
}

// afterTokens starts (or restarts) the syncer for the DEP name in the URL once its tokens were stored.
func (s *Service) afterTokens(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		h.ServeHTTP(rec, r)
		if rec.code < 300 && r.Method == http.MethodPut {
			s.mu.Lock()
			ctx := s.ctx
			s.mu.Unlock()
			if name := strings.TrimPrefix(r.URL.Path, "/"); name != "" && ctx != nil {
				s.Start(ctx, name)
			}
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(c int) { r.code = c; r.ResponseWriter.WriteHeader(c) }

// Run starts a syncer for every DEP name that has tokens and keeps the service alive until ctx ends. Names stored later are started when their tokens arrive.
func (s *Service) Run(ctx context.Context) error {
	s.mu.Lock()
	s.ctx = ctx
	s.mu.Unlock()
	res, err := s.Store.QueryDEPNames(ctx, &depstorage.DEPNamesQueryRequest{})
	if err != nil {
		return err
	}
	for _, name := range res.DEPNames {
		if _, err := s.Store.RetrieveAuthTokens(ctx, name); err == nil {
			s.Start(ctx, name)
		}
	}
	<-ctx.Done()
	return nil
}

// Start runs the syncer and assigner for a DEP name, replacing a running one.
func (s *Service) Start(ctx context.Context, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel, ok := s.running[name]; ok {
		cancel()
	}
	cctx, cancel := context.WithCancel(ctx)
	s.running[name] = cancel
	now := make(chan struct{}, 1)
	s.nows[name] = now

	assigner := depsync.NewAssigner(s.client, name, s.Store, depsync.WithAssignerLogger(s.logger.With("component", "dep-assigner")))
	cb := func(ctx context.Context, isFetch bool, resp *godep.FetchDeviceResponseJson) error {
		s.record(ctx, name, resp)
		if s.OnDevices != nil {
			s.OnDevices(ctx, name, isFetch, resp)
		}
		go func() {
			if err := assigner.ProcessDeviceResponse(context.WithoutCancel(ctx), resp); err != nil {
				s.logger.Info("msg", "dep assigner", "dep", name, "err", err)
			}
		}()
		return nil
	}
	syncer := depsync.NewSyncer(s.client, name, s.Store, depsync.WithLogger(s.logger.With("component", "dep-syncer")), depsync.WithSyncNow(now), depsync.WithCallback(cb), depsync.WithDuration(s.Interval))
	go func() {
		if err := syncer.Run(cctx); err != nil && cctx.Err() == nil {
			s.logger.Info("msg", "dep syncer stopped", "dep", name, "err", err)
		}
	}()
}

// SyncNow asks the syncer for name to run now; false if none is running.
func (s *Service) SyncNow(name string) bool {
	s.mu.Lock()
	c, ok := s.nows[name]
	s.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case c <- struct{}{}:
	default:
	}
	return true
}

func (s *Service) record(ctx context.Context, name string, resp *godep.FetchDeviceResponseJson) {
	if resp == nil {
		return
	}
	var ops []mongo.WriteModel
	for _, d := range resp.Devices {
		b, err := json.Marshal(d)
		if err != nil {
			continue
		}
		var m bson.M
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		serial, _ := m["serial_number"].(string)
		if serial == "" {
			continue
		}
		id := s.key(name, serial)
		if d.OpType != nil && *d.OpType == godep.DeviceJsonOpTypeDeleted {
			ops = append(ops, mongo.NewDeleteOneModel().SetFilter(bson.D{{Key: "_id", Value: id}}))
			continue
		}
		set := bson.D{{Key: "dep", Value: name}, {Key: "serial", Value: serial}, {Key: "device", Value: m}, {Key: "seen", Value: time.Now().UTC()}}
		if s.tid != "" {
			set = append(set, bson.E{Key: "t", Value: s.tid})
		}
		ops = append(ops, mongo.NewUpdateOneModel().SetFilter(bson.D{{Key: "_id", Value: id}}).SetUpdate(bson.D{{Key: "$set", Value: set}}).SetUpsert(true))
	}
	if len(ops) == 0 {
		return
	}
	if _, err := s.db.Collection(devicesCollection).BulkWrite(ctx, ops, options.BulkWrite().SetOrdered(false)); err != nil {
		s.logger.Info("msg", "recording DEP devices", "dep", name, "err", err)
	}
}

func (s *Service) devicesHandler(prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[len(prefix):]
		f := s.scope(bson.D{{Key: "dep", Value: name}})
		cur, err := s.db.Collection(devicesCollection).Find(r.Context(), f, options.Find().SetLimit(1000).SetSort(bson.D{{Key: "serial", Value: 1}}))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		var rows []struct {
			Serial string `bson:"serial"`
			Device bson.M `bson:"device"`
		}
		if err := cur.All(r.Context(), &rows); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		out := make([]bson.M, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.Device)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"devices": out})
	}
}

// key is the _id of a document keyed by the parts, with the tenant in front when tenants share the collection.
func (s *Service) key(parts ...string) string {
	k := strings.Join(parts, "\x1f")
	if s.tid == "" {
		return k
	}
	return s.tid + "\x1f" + k
}

// scope puts the tenant in front of a filter, when tenants share the collection.
func (s *Service) scope(f bson.D) bson.D {
	if s.tid == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, f...)
}

// MAIDJWT makes the token a device presents to sign in with a Managed Apple Account during account-driven enrollment: a JWT signed with the DEP name's token-exchange key, naming
// the MDM server as Apple Business Manager knows it.
func (s *Service) MAIDJWT(ctx context.Context, name string) (string, error) {
	detail, err := s.client.AccountDetail(ctx, name)
	if err != nil {
		return "", fmt.Errorf("account detail: %w", err)
	}
	if detail.ServerUuid == nil || *detail.ServerUuid == "" {
		return "", errors.New("Apple Business Manager did not name the MDM server")
	}
	_, keyPEM, err := s.Store.RetrieveCurrentTokenPKI(ctx, name)
	if err != nil {
		return "", fmt.Errorf("token key: %w", err)
	}
	key, err := cryptoutil.RSAKeyFromPEM(keyPEM)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	return cryptoutil.NewMAIDJWT(key, *detail.ServerUuid, time.Now(), hex.EncodeToString(jti))
}

// GetToken answers the device's GetToken check-in for com.apple.maid. Name is the DEP name to sign for; empty uses the only one there is.
func (s *Service) GetToken(name string) service.GetToken {
	return tokenFunc(func(r *mdm.Request, m *mdm.GetToken) (*mdm.GetTokenResponse, error) {
		n := name
		if n == "" {
			res, err := s.Store.QueryDEPNames(r.Context(), &depstorage.DEPNamesQueryRequest{})
			if err != nil {
				return nil, err
			}
			if len(res.DEPNames) != 1 {
				return nil, fmt.Errorf("%d DEP names: say which one signs Managed Apple Account tokens", len(res.DEPNames))
			}
			n = res.DEPNames[0]
		}
		jwt, err := s.MAIDJWT(r.Context(), n)
		if err != nil {
			return nil, err
		}
		return &mdm.GetTokenResponse{TokenData: []byte(jwt)}, nil
	})
}

type tokenFunc func(*mdm.Request, *mdm.GetToken) (*mdm.GetTokenResponse, error)

func (f tokenFunc) GetToken(r *mdm.Request, m *mdm.GetToken) (*mdm.GetTokenResponse, error) {
	return f(r, m)
}

// serialsOf lists the serial numbers recorded for a DEP name.
func (s *Service) serialsOf(ctx context.Context, name string) ([]string, error) {
	cur, err := s.db.Collection(devicesCollection).Find(ctx, s.scope(bson.D{{Key: "dep", Value: name}}), options.Find().SetProjection(bson.D{{Key: "serial", Value: 1}}))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Serial string `bson:"serial"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Serial
	}
	return out, nil
}

// Lookup says which DEP name a serial number is assigned to; ok is false for a device Apple has not assigned to this server.
func (s *Service) Lookup(ctx context.Context, serial string) (name string, ok bool, err error) {
	var row struct {
		Dep string `bson:"dep"`
	}
	err = s.db.Collection(devicesCollection).FindOne(ctx, s.scope(bson.D{{Key: "serial", Value: serial}})).Decode(&row)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", false, nil
	}
	return row.Dep, err == nil, err
}

// setProfileFacts records what the DEP name's profile promises, so that devices Apple assigns to it can be treated accordingly (supervised, held in Setup Assistant).
func (s *Service) setProfileFacts(ctx context.Context, name, uuid string, supervised, awaiting bool) error {
	return s.Store.set(ctx, name, bson.D{{Key: "profile_uuid", Value: uuid}, {Key: "profile_supervised", Value: supervised}, {Key: "profile_awaiting", Value: awaiting}})
}

// ProfileFacts returns what the DEP name's last defined profile promises (supervised true by default).
func (s *Service) ProfileFacts(ctx context.Context, name string) (supervised, awaiting bool) {
	var d struct {
		Supervised *bool `bson:"profile_supervised"`
		Awaiting   *bool `bson:"profile_awaiting"`
	}
	_ = s.Store.c.FindOne(ctx, bson.D{{Key: "_id", Value: s.Store.key(name)}}).Decode(&d)
	supervised, awaiting = true, true
	if d.Supervised != nil {
		supervised = *d.Supervised
	}
	if d.Awaiting != nil {
		awaiting = *d.Awaiting
	}
	return
}

// fetched builds a device response for the given serial numbers (tests and tools).
func fetched(serials ...string) *godep.FetchDeviceResponseJson {
	resp := &godep.FetchDeviceResponseJson{}
	added := godep.DeviceJsonOpTypeAdded
	for _, s := range serials {
		resp.Devices = append(resp.Devices, godep.DeviceJson{SerialNumber: s, Model: "MacBook Air", OpType: &added})
	}
	return resp
}
