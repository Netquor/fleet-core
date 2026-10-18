package mongodb

import (
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"
)

// parseConnString returns the database named in the URI path ("" when there is none).
func parseConnString(uri string) (string, error) {
	cs, err := connstring.Parse(uri)
	if err != nil {
		return "", err
	}
	return cs.Database, nil
}
