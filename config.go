package traefik_ocsp //nolint:all

type mode string

const (
	// RewriteMode activates the GET to POST request rewrite.
	RewriteMode mode = "rewrite"
	// CheckMode activates the OCSP certificate status check.
	CheckMode mode = "check"
)

// RewriteConfig defines GET request matching values.
type RewriteConfig struct {
	PathPrefixes []string `json:"pathPrefixes"`
	PathRegexp   string   `json:"pathRegexp"`
}

// IssuerConfig defines known issuer with its OCSP endpoint.
type IssuerConfig struct {
	OCSPEndpoint string `json:"ocspEndpoint"`
	IssuerPEM    string `json:"issuerPem"`
}

// Config holds the plugin configuration.
type Config struct {
	Mode mode `json:"mode"`
	// When mode=rewrite (default)
	Rewrite RewriteConfig `json:"rewrite"`
	// When mode=check
	Issuers []IssuerConfig `json:"issuers"`
	// Debugging requests
	Debug bool `json:"debug"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Mode: RewriteMode,
		Rewrite: RewriteConfig{
			PathPrefixes: []string{"/ocsp"},
			PathRegexp:   "",
		},
		Issuers: []IssuerConfig{},
		Debug:   false,
	}
}
