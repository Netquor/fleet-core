package blueprints

import "go.mongodb.org/mongo-driver/v2/bson"

func bsonDTags(t []string) bson.D   { return bson.D{{Key: "tags", Value: t}} }
func bsonDGroups(g []string) bson.D { return bson.D{{Key: "groups", Value: g}} }
