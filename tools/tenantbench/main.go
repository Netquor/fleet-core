// tenantbench compares what it costs to bring a new tenant onto a NanoMDM storage backend, and how the backend behaves with a large amount of data, on PostgreSQL and MongoDB.
//
//	go run ./tools/tenantbench -pg 'postgres://postgres:bench@127.0.0.1:55432/postgres?sslmode=disable' -mongo 'mongodb://127.0.0.1:27117/?replicaSet=rs0'
//
// 1. Provisioning: N new tenants, one after another. PostgreSQL three ways (a database and the schema; a database cloned from a template; a schema in one shared database) and
// MongoDB two ways (a new client and database with its indexes, which is a stack's first start; the indexes alone on an open client).
// 2. Seeding: M tenants of D devices each, with commands and results, through the storage interface, so both backends get exactly the same traffic.
// 3. Operations on the seeded data from W workers: a check-in, fetching the next command, acknowledging it, queueing a command for 100 devices.
// 4. What it takes on disk.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage"
	"github.com/micromdm/nanomdm/storage/mongodb"
	"github.com/micromdm/nanomdm/storage/pgsql"

	_ "github.com/lib/pq"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var (
	pgAdmin   = flag.String("pg", "", "PostgreSQL admin DSN (a role that can create databases)")
	mongoURI  = flag.String("mongo", "", "MongoDB URI (a replica set)")
	nProv     = flag.Int("provision", 100, "tenants to provision for the provisioning test")
	nTenants  = flag.Int("tenants", 20, "tenants to seed")
	nDevices  = flag.Int("devices", 1000, "devices per seeded tenant")
	nCommands = flag.Int("commands", 5, "commands queued for every device")
	workers   = flag.Int("workers", 16, "concurrent workers")
	opSeconds = flag.Int("seconds", 6, "seconds per operation test per round")
	rounds    = flag.Int("rounds", 3, "rounds per operation, alternating the backends")
	prefix    = flag.String("prefix", "tb", "name prefix for the databases made (all are dropped at the end)")
	only      = flag.String("provision-only", "", "provisioning test only, for these backends (pg, mongo, or pg,mongo); no seeding or operations")
)

type stat struct {
	name string
	d    []time.Duration
}

func (s *stat) add(d time.Duration) { s.d = append(s.d, d) }
func (s *stat) report(wall time.Duration) string {
	if len(s.d) == 0 {
		return fmt.Sprintf("%-34s no samples", s.name)
	}
	d := append([]time.Duration(nil), s.d...)
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	q := func(p float64) time.Duration { return d[int(float64(len(d)-1)*p)] }
	var sum time.Duration
	for _, x := range d {
		sum += x
	}
	out := fmt.Sprintf("%-34s n=%-6d mean=%-9s p50=%-9s p95=%-9s p99=%-9s max=%-9s", s.name, len(d), sum/time.Duration(len(d)), q(.5), q(.95), q(.99), d[len(d)-1])
	if wall > 0 {
		out += fmt.Sprintf(" %7.0f ops/s", float64(len(d))/wall.Seconds())
	}
	return out
}

func main() {
	flag.Parse()
	if *pgAdmin == "" || *mongoURI == "" {
		fmt.Fprintln(os.Stderr, "need -pg and -mongo")
		os.Exit(2)
	}
	ctx := context.Background()
	admin, err := sql.Open("postgres", *pgAdmin)
	must(err)
	defer admin.Close()
	mc, err := mongo.Connect(options.Client().ApplyURI(*mongoURI).SetMaxPoolSize(uint64(*workers * 2)))
	must(err)
	defer mc.Disconnect(ctx)
	must(mc.Ping(ctx, nil))
	cleanup(ctx, admin, mc)
	defer cleanup(ctx, admin, mc)

	fmt.Printf("== provisioning %d tenants ==\n", *nProv)
	provision(ctx, admin, mc)
	if *only != "" {
		return
	}

	fmt.Printf("\n== seeding %d tenants x %d devices, %d commands each ==\n", *nTenants, *nDevices, *nCommands)
	pg := seedPG(ctx, admin)
	mg := seedMongo(ctx, mc)
	ms := seedMongoShared(ctx, mc)

	fmt.Printf("\n== operations on the seeded data, %d workers, %d rounds of %ds each, backends alternating ==\n", *workers, *rounds, *opSeconds)
	operations(ctx, []*backend{pg, mg, ms})

	fmt.Println("\n== size on disk ==")
	var pgBytes int64
	for _, t := range pg.tenants {
		var n int64
		must(admin.QueryRow(`SELECT pg_database_size($1)`, t.name).Scan(&n))
		pgBytes += n
	}
	var mgBytes, mgData int64
	for _, t := range mg.tenants {
		var st bson.M
		must(mc.Database(t.name).RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&st))
		mgBytes += asInt(st["storageSize"]) + asInt(st["indexSize"])
		mgData += asInt(st["dataSize"])
	}
	var shBytes, shData int64
	{
		var st bson.M
		must(mc.Database(ms.tenants[0].name).RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&st))
		shBytes, shData = asInt(st["storageSize"])+asInt(st["indexSize"]), asInt(st["dataSize"])
	}
	fmt.Printf("PostgreSQL: %s in %d databases\n", human(pgBytes), len(pg.tenants))
	fmt.Printf("MongoDB, database per tenant: %s on disk (%s of data) in %d databases\n", human(mgBytes), human(mgData), len(mg.tenants))
	fmt.Printf("MongoDB, shared collections:  %s on disk (%s of data) in 1 database\n", human(shBytes), human(shData))
}

func asInt(v any) int64 {
	switch t := v.(type) {
	case int32:
		return int64(t)
	case int64:
		return t
	case float64:
		return int64(t)
	}
	return 0
}
func human(b int64) string { return fmt.Sprintf("%.1f MB", float64(b)/1e6) }
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cleanup(ctx context.Context, admin *sql.DB, mc *mongo.Client) {
	rows, err := admin.Query(`SELECT datname FROM pg_database WHERE datname LIKE $1`, *prefix+"\\_%")
	if err == nil {
		var names []string
		for rows.Next() {
			var n string
			_ = rows.Scan(&n)
			names = append(names, n)
		}
		rows.Close()
		for _, n := range names {
			_, _ = admin.Exec(`DROP DATABASE IF EXISTS "` + n + `" WITH (FORCE)`)
		}
	}
	_, _ = admin.Exec(`DROP DATABASE IF EXISTS "` + *prefix + `_template" WITH (FORCE)`)
	if names, err := mc.ListDatabaseNames(ctx, bson.D{{Key: "name", Value: bson.D{{Key: "$regex", Value: "^" + *prefix + "_"}}}}); err == nil {
		for _, n := range names {
			_ = mc.Database(n).Drop(ctx)
		}
	}
}

// ---- provisioning ----

func provision(ctx context.Context, admin *sql.DB, mc *mongo.Client) {
	want := func(b string) bool { return *only == "" || strings.Contains(*only, b) }
	run := func(name string, fn func(i int) error) {
		if (strings.HasPrefix(name, "pg") && !want("pg")) || (strings.HasPrefix(name, "mongo") && !want("mongo")) {
			return
		}
		s := &stat{name: name}
		start := time.Now()
		for i := 0; i < *nProv; i++ {
			t := time.Now()
			must(fn(i))
			s.add(time.Since(t))
		}
		fmt.Println(s.report(0))
		n := len(s.d)
		if n >= 20 {
			avg := func(d []time.Duration) time.Duration {
				var t time.Duration
				for _, x := range d {
					t += x
				}
				return t / time.Duration(len(d))
			}
			fmt.Printf("%-34s first 10 mean=%s, last 10 mean=%s, total %s\n", "", avg(s.d[:10]), avg(s.d[n-10:]), time.Since(start).Round(time.Millisecond))
		}
	}
	// PostgreSQL (a): a database and the schema, on a fresh connection (what a new stack does on first start).
	run("pg: create database + schema", func(i int) error {
		name := fmt.Sprintf("%s_pa_%d", *prefix, i)
		if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
			return err
		}
		db, err := sql.Open("postgres", withDB(*pgAdmin, name))
		if err != nil {
			return err
		}
		defer db.Close()
		_, err = db.Exec(pgsql.Schema)
		return err
	})
	// PostgreSQL (b): clone a prepared template database.
	tmpl := *prefix + "_template"
	_, err := admin.Exec(`CREATE DATABASE "` + tmpl + `"`)
	must(err)
	tdb, err := sql.Open("postgres", withDB(*pgAdmin, tmpl))
	must(err)
	_, err = tdb.Exec(pgsql.Schema)
	must(err)
	tdb.Close()
	run("pg: create database from template", func(i int) error {
		_, err := admin.Exec(fmt.Sprintf(`CREATE DATABASE "%s_pb_%d" TEMPLATE "%s"`, *prefix, i, tmpl))
		return err
	})
	// PostgreSQL (c): a schema in one shared database.
	shared := *prefix + "_shared"
	_, err = admin.Exec(`CREATE DATABASE "` + shared + `"`)
	must(err)
	sdb, err := sql.Open("postgres", withDB(*pgAdmin, shared))
	must(err)
	defer sdb.Close()
	run("pg: create schema + tables (shared db)", func(i int) error {
		name := fmt.Sprintf("t%d", i)
		tx, err := sdb.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`CREATE SCHEMA ` + name); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.Exec(`SET LOCAL search_path TO ` + name); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.Exec(pgsql.Schema); err != nil {
			_ = tx.Rollback()
			return err
		}
		return tx.Commit()
	})
	// MongoDB (a): a new client and database with its indexes (a stack's first start).
	run("mongo: new client + database + indexes", func(i int) error {
		s, err := mongodb.New(ctx, mongodb.WithURI(*mongoURI), mongodb.WithDatabase(fmt.Sprintf("%s_ma_%d", *prefix, i)))
		if err != nil {
			return err
		}
		return s.Close(ctx)
	})
	// MongoDB (b): the indexes alone, on a client that is already open.
	run("mongo: indexes on an open client", func(i int) error {
		s, err := mongodb.New(ctx, mongodb.WithClient(mc), mongodb.WithDatabase(fmt.Sprintf("%s_mb_%d", *prefix, i)))
		return err2(s, err)
	})
	sharedDB := *prefix + "_prov_shared"
	if want("mongo") {
		_, err := mongodb.New(ctx, mongodb.WithClient(mc), mongodb.WithDatabase(sharedDB), mongodb.WithTenant("t-init")) // the indexes, once for everyone
		must(err)
	}
	run("mongo: shared collections, bind a tenant", func(i int) error {
		_, err := mongodb.New(ctx, mongodb.WithClient(mc), mongodb.WithDatabase(sharedDB), mongodb.WithTenant(fmt.Sprintf("t%d", i)), mongodb.WithoutIndexes())
		if err != nil {
			return err
		}
		_, err = mc.Database(sharedDB).Collection("tenants").InsertOne(ctx, bson.D{{Key: "_id", Value: fmt.Sprintf("t%d", i)}})
		return err
	})
	run("mongo: no work (shared collections)", func(i int) error {
		_, err := mc.Database(*prefix+"_registry").Collection("tenants").InsertOne(ctx, bson.D{{Key: "_id", Value: fmt.Sprintf("t%d", i)}})
		return err
	})
}

func err2(_ *mongodb.MongoDBStorage, err error) error { return err }

func withDB(dsn, db string) string {
	i := strings.Index(dsn, "?")
	base, q := dsn, ""
	if i >= 0 {
		base, q = dsn[:i], dsn[i:]
	}
	j := strings.LastIndex(base, "/")
	return base[:j+1] + db + q
}

// ---- seeding and operations ----

type tenant struct {
	name    string
	store   storage.AllStorage
	devices []string
	uuids   [][]string // per device: the command uuids queued
}

type backend struct {
	name    string
	tenants []*tenant
}

func req(ctx context.Context, id string) *mdm.Request {
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{Type: mdm.Device, ID: id}
	return r
}

func authMsg(udid string) *mdm.Authenticate {
	raw := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>BuildVersion</key><string>24A335</string><key>MessageType</key><string>Authenticate</string><key>OSVersion</key><string>15.0</string><key>ProductName</key><string>Mac15,6</string><key>SerialNumber</key><string>C02%s</string><key>Topic</key><string>com.apple.mgmt.External.bench</string><key>UDID</key><string>%s</string></dict></plist>`, udid[:8], udid)
	a := &mdm.Authenticate{Topic: "com.apple.mgmt.External.bench", SerialNumber: "C02" + udid[:8], Raw: []byte(raw)}
	a.UDID, a.MessageType.MessageType = udid, "Authenticate"
	return a
}

func tokenMsg(udid string) *mdm.TokenUpdate {
	raw := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>AwaitingConfiguration</key><false/><key>MessageType</key><string>TokenUpdate</string><key>PushMagic</key><string>%s</string><key>Token</key><data>AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=</data><key>Topic</key><string>com.apple.mgmt.External.bench</string><key>UDID</key><string>%s</string></dict></plist>`, udid, udid)
	t := &mdm.TokenUpdate{Raw: []byte(raw)}
	t.UDID, t.MessageType.MessageType = udid, "TokenUpdate"
	t.Topic, t.PushMagic = "com.apple.mgmt.External.bench", udid
	_ = t.SetTokenString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	return t
}

func commandMsg(uuid string) *mdm.Command {
	raw := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Command</key><dict><key>RequestType</key><string>DeviceInformation</string><key>Queries</key><array><string>OSVersion</string><string>DeviceName</string><string>SerialNumber</string></array></dict><key>CommandUUID</key><string>%s</string></dict></plist>`, uuid)
	c := &mdm.Command{CommandUUID: uuid, Raw: []byte(raw)}
	c.Command.RequestType = "DeviceInformation"
	return c
}

// resultMsg is a DeviceInformation-sized answer (about 2 KB, like a real one).
func resultMsg(uuid, status string) *mdm.CommandResults {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CommandUUID</key><string>` + uuid + `</string><key>Status</key><string>` + status + `</string><key>QueryResponses</key><dict>`)
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, `<key>Field%d</key><string>value-%d-%s</string>`, i, i, uuid[:8])
	}
	b.WriteString(`<key>BatteryLevel</key><real>0.83</real><key>IsSupervised</key><true/><key>Capacity</key><integer>494384795648</integer></dict></dict></plist>`)
	r := &mdm.CommandResults{CommandUUID: uuid, Status: status, Raw: []byte(b.String())}
	return r
}

func uuidN(rng *rand.Rand) string {
	const hexd = "0123456789ABCDEF"
	b := make([]byte, 36)
	for i := range b {
		switch i {
		case 8, 13, 18, 23:
			b[i] = '-'
		default:
			b[i] = hexd[rng.Intn(16)]
		}
	}
	return string(b)
}

func seed(ctx context.Context, name string, newTenant func(i int) (*tenant, error)) *backend {
	b := &backend{name: name}
	start := time.Now()
	var calls atomic.Int64
	for i := 0; i < *nTenants; i++ {
		t, err := newTenant(i)
		must(err)
		rng := rand.New(rand.NewSource(int64(i)*7919 + 1))
		t.devices = make([]string, *nDevices)
		t.uuids = nil
		for d := range t.devices {
			t.devices[d] = strings.ToUpper(uuidN(rng))
		}
		cmdIDs := make([]string, *nCommands)
		for c := range cmdIDs {
			cmdIDs[c] = uuidN(rng)
		}
		var wg sync.WaitGroup
		jobs := make(chan int, 256)
		for w := 0; w < *workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for d := range jobs {
					id := t.devices[d]
					must(t.store.StoreAuthenticate(req(ctx, id), authMsg(id)))
					must(t.store.StoreTokenUpdate(req(ctx, id), tokenMsg(id)))
					calls.Add(2)
				}
			}()
		}
		for d := range t.devices {
			jobs <- d
		}
		close(jobs)
		wg.Wait()
		// Queue every command for every device, then have 60% of devices answer all of them.
		for _, id := range cmdIDs {
			_, err := t.store.EnqueueCommand(ctx, t.devices, commandMsg(id))
			must(err)
			calls.Add(1)
		}
		jobs = make(chan int, 256)
		for w := 0; w < *workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for d := range jobs {
					for _, id := range cmdIDs {
						must(t.store.StoreCommandReport(req(ctx, t.devices[d]), resultMsg(id, "Acknowledged")))
						calls.Add(1)
					}
				}
			}()
		}
		for d := 0; d < len(t.devices)*6/10; d++ {
			jobs <- d
		}
		close(jobs)
		wg.Wait()
		t.uuids = [][]string{cmdIDs}
		b.tenants = append(b.tenants, t)
	}
	el := time.Since(start)
	fmt.Printf("%-10s seeded %d tenants / %d devices in %s (%d storage calls, %.0f calls/s)\n", name, *nTenants, *nTenants**nDevices, el.Round(time.Millisecond), calls.Load(), float64(calls.Load())/el.Seconds())
	return b
}

func seedPG(ctx context.Context, admin *sql.DB) *backend {
	return seed(ctx, "postgres", func(i int) (*tenant, error) {
		name := fmt.Sprintf("%s_seed_pg_%d", *prefix, i)
		if _, err := admin.Exec(`CREATE DATABASE "` + name + `" TEMPLATE "` + *prefix + `_template"`); err != nil {
			return nil, err
		}
		db, err := sql.Open("postgres", withDB(*pgAdmin, name))
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(6)
		s, err := pgsql.New(pgsql.WithDB(db))
		return &tenant{name: name, store: s}, err
	})
}

// seedMongoShared: every tenant in the same collections of one database, each store bound to its tenant.
func seedMongoShared(ctx context.Context, mc *mongo.Client) *backend {
	db := *prefix + "_shared_mg"
	first, err := mongodb.New(ctx, mongodb.WithClient(mc), mongodb.WithDatabase(db), mongodb.WithTenant("t-init"))
	must(err)
	_ = first
	return seed(ctx, "mongo-shared", func(i int) (*tenant, error) {
		s, err := mongodb.New(ctx, mongodb.WithClient(mc), mongodb.WithDatabase(db), mongodb.WithTenant(fmt.Sprintf("t%d", i)), mongodb.WithoutIndexes())
		return &tenant{name: db, store: s}, err
	})
}

func seedMongo(ctx context.Context, mc *mongo.Client) *backend {
	return seed(ctx, "mongodb", func(i int) (*tenant, error) {
		name := fmt.Sprintf("%s_seed_mg_%d", *prefix, i)
		s, err := mongodb.New(ctx, mongodb.WithClient(mc), mongodb.WithDatabase(name))
		return &tenant{name: name, store: s}, err
	})
}

type op struct {
	name string
	fn   func(rng *rand.Rand, t *tenant) error
}

func opList(ctx context.Context) []op {
	return []op{
		{"check-in (TokenUpdate)", func(rng *rand.Rand, t *tenant) error {
			id := t.devices[rng.Intn(len(t.devices))]
			return t.store.StoreTokenUpdate(req(ctx, id), tokenMsg(id))
		}},
		{"fetch next command", func(rng *rand.Rand, t *tenant) error {
			_, err := t.store.RetrieveNextCommand(req(ctx, t.devices[rng.Intn(len(t.devices))]), false)
			return err
		}},
		{"acknowledge a command", func(rng *rand.Rand, t *tenant) error {
			id := t.devices[rng.Intn(len(t.devices))]
			return t.store.StoreCommandReport(req(ctx, id), resultMsg(t.uuids[0][rng.Intn(len(t.uuids[0]))], "Acknowledged"))
		}},
		{"queue a command for 100 devices", func(rng *rand.Rand, t *tenant) error {
			seen := map[string]bool{}
			var uniq []string
			for i := 0; i < 100; i++ {
				id := t.devices[rng.Intn(len(t.devices))]
				if !seen[id] {
					seen[id] = true
					uniq = append(uniq, id)
				}
			}
			_, err := t.store.EnqueueCommand(ctx, uniq, commandMsg(uuidN(rng)))
			return err
		}},
	}
}

// runOp drives one operation from the workers for the given time against one backend.
func runOp(b *backend, o op, seconds int, into *stat, wall *time.Duration) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	stop := time.Now().Add(time.Duration(seconds) * time.Second)
	start := time.Now()
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(w) + time.Now().UnixNano()))
			var local []time.Duration
			for time.Now().Before(stop) {
				t := b.tenants[rng.Intn(len(b.tenants))]
				st := time.Now()
				if err := o.fn(rng, t); err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v\n", o.name, err)
					break
				}
				local = append(local, time.Since(st))
			}
			mu.Lock()
			into.d = append(into.d, local...)
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	*wall += time.Since(start)
}

// operations runs each operation on every backend in turn, several rounds, alternating the backends, so machine drift (other processes, heat) lands on both alike.
func operations(ctx context.Context, backends []*backend) {
	for _, o := range opList(ctx) {
		stats := map[string]*stat{}
		walls := map[string]*time.Duration{}
		for _, b := range backends {
			stats[b.name], walls[b.name] = &stat{name: b.name + ": " + o.name}, new(time.Duration)
		}
		for r := 0; r < *rounds; r++ {
			order := append(append([]*backend{}, backends[r%len(backends):]...), backends[:r%len(backends)]...)
			for _, b := range order {
				runOp(b, o, *opSeconds, stats[b.name], walls[b.name])
			}
		}
		for _, b := range backends {
			fmt.Println(stats[b.name].report(*walls[b.name]))
		}
	}
}
