// Package api holds the OpenAPI specification of the admin REST API
// (openapi.yaml). The spec is written first; handlers follow it (ADR-05).
package api

import _ "embed"

// Spec is the OpenAPI document, embedded so the server can serve it later.
//
//go:embed openapi.yaml
var Spec []byte
