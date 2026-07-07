// Package web embeds the HTML templates so the server ships as a single binary.
package web

import "embed"

// FS holds the compiled-in template files under templates/.
//
//go:embed templates/*.html
var FS embed.FS
