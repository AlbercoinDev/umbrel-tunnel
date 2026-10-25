// Package webui embeds the minimal administration dashboard.
package webui

import "embed"

// FS contains the static dashboard assets.
//
//go:embed index.html app.js style.css
var FS embed.FS
