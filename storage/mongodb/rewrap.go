package mongodb

import (
	"context"
	"errors"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Rewrap seals every secret with the sealer's current key: values stored before sealing was on, and those under an older key. It also drops the readable native copies of what it
// seals. It returns how many documents it changed; run it again after rotating the master key until it reports none.
func (s *MongoDBStorage) Rewrap(ctx context.Context) (int, error) {
	if s.sealer == nil {
		return 0, errors.New("no sealer configured")
	}
	current := func(v string) bool {
		c, ok := s.sealer.(interface{ Current(string) bool })
		return ok && strings.HasPrefix(v, "s1.") && c.Current(v)
	}
	total := 0
	// field: the purpose it is sealed for. docs are the readable copies that go once the raw is sealed.
	type spec struct {
		coll   string
		fields map[string]string
		docs   []string
		raw    bool // the value is bytes (unlock_token), not text
	}
	for _, sp := range []spec{
		{cCommands, map[string]string{"command": "mdm.command"}, []string{"command_doc"}, false},
		{cQueue, map[string]string{"result": "mdm.result"}, []string{"result_doc"}, false},
		{cDevices, map[string]string{"token_update": "mdm.token_update", "bootstrap_token_b64": "mdm.bootstrap", "user_authenticate": "mdm.user_authenticate", "user_authenticate_digest": "mdm.user_authenticate"}, []string{"token_update_doc"}, false},
		{cUsers, map[string]string{"token_update": "mdm.token_update", "user_authenticate": "mdm.user_authenticate", "user_authenticate_digest": "mdm.user_authenticate"}, []string{"token_update_doc"}, false},
		{cPushCerts, map[string]string{"key_pem": "mdm.pushkey"}, nil, false},
	} {
		cur, err := s.db.Collection(sp.coll).Find(ctx, s.scope(bson.D{}))
		if err != nil {
			return total, err
		}
		var rows []bson.M
		if err := cur.All(ctx, &rows); err != nil {
			return total, err
		}
		for _, r := range rows {
			set, unset := bson.D{}, bson.D{}
			for field, purpose := range sp.fields {
				v, ok := r[field].(string)
				if !ok || v == "" || current(v) {
					continue
				}
				plain, err := s.open(purpose, v)
				if err != nil {
					return total, err
				}
				sealed, err := s.sealer.Seal(purpose, plain)
				if err != nil {
					return total, err
				}
				set = append(set, bson.E{Key: field, Value: sealed})
				for _, d := range sp.docs {
					if strings.HasPrefix(field, strings.TrimSuffix(d, "_doc")) {
						unset = append(unset, bson.E{Key: d, Value: ""})
					}
				}
			}
			// The unlock token is bytes when stored unsealed.
			if b, ok := r["unlock_token"].(bson.Binary); ok && sp.coll == cDevices {
				sealed, err := s.sealer.Seal("mdm.unlock_token", b.Data)
				if err != nil {
					return total, err
				}
				set = append(set, bson.E{Key: "unlock_token", Value: sealed})
			} else if v, ok := r["unlock_token"].(string); ok && sp.coll == cDevices && !current(v) {
				plain, err := s.open("mdm.unlock_token", v)
				if err != nil {
					return total, err
				}
				sealed, err := s.sealer.Seal("mdm.unlock_token", plain)
				if err != nil {
					return total, err
				}
				set = append(set, bson.E{Key: "unlock_token", Value: sealed})
			}
			if len(set) == 0 {
				continue
			}
			upd := bson.D{{Key: "$set", Value: set}}
			if len(unset) > 0 {
				upd = append(upd, bson.E{Key: "$unset", Value: unset})
			}
			// tenant-ok: _id comes from the scoped read above
			if _, err := s.db.Collection(sp.coll).UpdateOne(ctx, bson.D{{Key: "_id", Value: r["_id"]}}, upd); err != nil {
				return total, err
			}
			total++
		}
	}
	return total, nil
}
