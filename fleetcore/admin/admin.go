// Package admin carries who is calling the management API through a request, so that what a person does with it (revealing a recovery key, wiping a device) is recorded under their name.
package admin

import "context"

type key struct{}

// With returns a context that remembers who is calling.
func With(ctx context.Context, who string) context.Context { return context.WithValue(ctx, key{}, who) }

// Who returns who is calling, or "unknown".
func Who(ctx context.Context) string {
	if w, ok := ctx.Value(key{}).(string); ok && w != "" {
		return w
	}
	return "unknown"
}
