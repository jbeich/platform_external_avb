// Package tiles contains methods to work with tlog based verifiable logs.
package tiles

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"google3/third_party/golang/go_mod/sumdb/tlog/tlog"
)

// HashReader implements tlog.HashReader, reading from tlog-based log located at
// URL.
type HashReader struct {
	URL string
}

// ReadHashes implements tlog.HashReader's ReadHashes.
// See: https://pkg.go.dev/golang.org/x/mod/sumdb/tlog#HashReader.
func (h HashReader) ReadHashes(indices []int64) ([]tlog.Hash, error) {
	tiles := make(map[string][]byte)
	hashes := make([]tlog.Hash, 0, len(indices))
	for _, index := range indices {
		// The PixelBT log is tiled at height = 1.
		tile := tlog.TileForIndex(1, index)

		var content []byte
		var exists bool
		var err error
		content, exists = tiles[tile.Path()]
		if !exists {
			content, err = readFromURL(h.URL, tile.Path())
			if err != nil {
				return nil, fmt.Errorf("failed to read from %s: %v", tile.Path(), err)
			}
			tiles[tile.Path()] = content
		}

		hash, err := tlog.HashFromTile(tile, content, index)
		if err != nil {
			return nil, fmt.Errorf("failed to read data from tile for index %d: %v", index, err)
		}
		hashes = append(hashes, hash)
	}
	return hashes, nil
}

func readFromURL(base, suffix string) ([]byte, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %s: %v", base, err)
	}
	u.Path = path.Join(u.Path, suffix)

	resp, err := http.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("http.Get(%s): %v", u.String(), err)
	}
	defer resp.Body.Close()
	if code := resp.StatusCode; code != 200 {
		return nil, fmt.Errorf("http.Get(%s): %s", u.String(), http.StatusText(code))
	}

	return io.ReadAll(resp.Body)
}
