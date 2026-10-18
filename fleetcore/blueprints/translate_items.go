package blueprints

import (
	"fmt"
	"strings"

	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
)

// TranslationItems turns what the profile translator produced into blueprint items: one asset item per asset (certificates, identities, credentials, which the
// declarations refer to by "$asset:<id>") and one declaration item per translated payload that has settings. name is a short label for the payloads, by position.
// An asset that two payloads both produce (the same id and content) appears once; the same id with different content is an error, because the references would be ambiguous.
func TranslationItems(rows []TranslationRow, prefix string) ([]Item, error) {
	var items []Item
	seen := map[string]Item{}
	for n, row := range rows {
		tr := row.Translation
		if tr == nil {
			continue
		}
		for _, a := range tr.Assets {
			it := Item{ID: a.ID, Kind: "asset", Name: row.Name, DeclarationType: a.DeclarationType, AssetData: a.Data, ContentType: a.ContentType}
			if prev, ok := seen[a.ID]; ok {
				if prev.Hash() != it.Hash() {
					return nil, fmt.Errorf("two payloads produce the asset %s with different content", a.ID)
				}
				continue
			}
			seen[a.ID] = it
			items = append(items, it)
		}
		def, ok := schemas.Current().Declaration(tr.Declaration)
		if !ok || def.Kind == "asset" || len(tr.Payload) == 0 {
			continue
		}
		short := tr.Declaration[strings.LastIndex(tr.Declaration, ".")+1:]
		id := fmt.Sprintf("%s%s-%d", prefix, short, n+1)
		items = append(items, Item{ID: id, Kind: "declaration", Name: row.Name, DeclarationType: tr.Declaration, Declaration: tr.Payload})
	}
	return items, nil
}

// TranslationRow is one translated payload with the name to give its items.
type TranslationRow struct {
	Name        string
	PayloadType string
	Translation *ddm.Translation
}

// mergeItems adds items to a blueprint, replacing any with the same id.
func mergeItems(b *Blueprint, items []Item) {
	for _, it := range items {
		replaced := false
		for i := range b.Items {
			if b.Items[i].ID == it.ID {
				b.Items[i], replaced = it, true
			}
		}
		if !replaced {
			b.Items = append(b.Items, it)
		}
	}
}
