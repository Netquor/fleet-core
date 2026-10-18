// genschemas builds the snapshot of Apple's device-management definitions that is compiled into the binary (fleetcore/schemas/schemas.json).
// The server can also follow Apple's releases at runtime (schemas.Refresher); this keeps the built-in copy current for new builds and for air-gapped installs.
//
//	go run ./tools/genschemas                         (downloads the release branch)
//	go run ./tools/genschemas -ref <branch|tag|sha>
//	go run ./tools/genschemas -dir /path/to/device-management
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
)

func main() {
	dir := flag.String("dir", "", "checkout of apple/device-management")
	ref := flag.String("ref", "release", "git ref to download when -dir is not given")
	out := flag.String("out", "fleetcore/schemas/schemas.json", "output file")
	flag.Parse()
	var set *schemas.Set
	var err error
	if *dir != "" {
		set, err = schemas.ParseDir(*dir, *ref)
	} else {
		var resp *http.Response
		if resp, err = http.Get("https://codeload.github.com/apple/device-management/tar.gz/" + *ref); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			} else {
				set, err = schemas.ParseTarGz(resp.Body, *ref)
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b, _ := json.Marshal(set)
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%d commands, %d profile payloads -> %s (%d bytes)\n", len(set.Commands), len(set.Profiles), *out, len(b))
}
