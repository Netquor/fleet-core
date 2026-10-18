package dep

import (
	"context"
	"encoding/json"
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
	tokens.Handle("GET", api.RetrieveAuthTokensHandler(s.Store, l.With("handler", "dep-get-tokens")))
	strip("/tokens/", tokens)

	config := dephttp.NewMethodMux()
	config.Handle("GET", api.RetrieveConfigHandler(s.Store, l.With("handler", "dep-get-config")))
	config.Handle("PUT", api.StoreConfigHandler(s.Store, l.With("handler", "dep-store-config")))
	strip("/config/", config)

	pkiMux := dephttp.NewMethodMux()
	pkiMux.Handle("GET", api.GetCertTokenPKIHandler(s.Store, l.With("handler", "dep-get-token-pki")))
	pkiMux.Handle("PUT", s.afterTokens(api.DecryptTokenPKIHandler(s.Store, s.Store, l.With("handler", "dep-put-token-pki"))))
	strip("/tokenpki/", pkiMux)

	assigner := dephttp.NewMethodMux()
	assigner.Handle("GET", api.RetrieveAssignerProfileHandler(s.Store, l.With("handler", "dep-get-assigner")))
	assigner.Handle("PUT", api.StoreAssignerProfileHandler(s.Store, l.With("handler", "dep-store-assigner")))
	strip("/assigner/", assigner)

	names := dephttp.NewMethodMux()
	names.Handle("GET", apinext.NewQueryDEPNamesHandler(s.Store, l.With("handler", "dep-names")))
	strip("/names", names)

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
		id := name + "\x1f" + serial
		if s.tid != "" {
			id = s.tid + "\x1f" + id
		}
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
		f := bson.D{{Key: "dep", Value: name}}
		if s.tid != "" {
			f = append(f, bson.E{Key: "t", Value: s.tid})
		}
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
