// Package controlv3 embeds the implemented v3 API contract. Future endpoints
// are added only when their handlers and authorization are available.
package controlv3

import _ "embed"

//go:embed openapi.yaml
var OpenAPI []byte
