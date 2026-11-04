package edge

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/abdusalomovrustambek/auth-gateway/internal/httpx"
)

// Static serves the web app from root, for requests no other route handled:
//
//   - a path that names an existing file is served as is;
//   - a GET whose Accept includes text/html and whose last segment has no
//     extension gets index.html (the single-page app routes it);
//   - everything else is 404.
//
// Paths are cleaned as rooted paths, so ".." cannot leave root.
func Static(root string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			httpx.Error(c, http.StatusNotFound, "not found")
			return
		}
		rel := path.Clean("/" + c.Request.URL.Path)
		if file := regularFile(filepath.Join(root, filepath.FromSlash(rel))); file != "" {
			serveFile(c, file, false)
			return
		}
		if acceptsHTML(c.Request) && path.Ext(path.Base(rel)) == "" {
			if index := regularFile(filepath.Join(root, "index.html")); index != "" {
				serveFile(c, index, true)
				return
			}
		}
		httpx.Error(c, http.StatusNotFound, "not found")
	}
}

// regularFile returns name if it is a regular file, else "".
func regularFile(name string) string {
	fi, err := os.Stat(name)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	return name
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

func serveFile(c *gin.Context, name string, noCache bool) {
	f, err := os.Open(name)
	if err != nil {
		httpx.Error(c, http.StatusNotFound, "not found")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		httpx.Error(c, http.StatusNotFound, "not found")
		return
	}
	if noCache {
		c.Header("Cache-Control", "no-cache")
	}
	http.ServeContent(c.Writer, c.Request, fi.Name(), fi.ModTime(), f)
}
