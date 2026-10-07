package assets

import "embed"

//go:embed *.yaml *.yar *.json *.sh
var Files embed.FS
