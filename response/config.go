package response

// Config defines framework-wide configuration for request/response envelopes and pagination.
type Config struct {
	// DefaultPageSize is the default number of items per page if not specified in query.
	// Default: 20.
	DefaultPageSize int

	// MaxPageSize is the maximum allowed items per page to prevent client DoS.
	// Default: 100.
	MaxPageSize int

	// EnableLinks enables RFC 5988 / JSON:API HATEOAS links in paginated envelopes.
	// Default: true.
	EnableLinks bool

	// EnableLinkHeader sets the standard RFC 5988 "Link" HTTP header on paginated responses.
	// Default: true.
	EnableLinkHeader bool

	// EnableDurationMeta includes execution latency/duration in the response metadata.
	// Default: true.
	EnableDurationMeta bool
}

// DefaultConfig returns safe-by-default enterprise envelope configuration.
func DefaultConfig() Config {
	return Config{
		DefaultPageSize:    20,
		MaxPageSize:        100,
		EnableLinks:        true,
		EnableLinkHeader:   true,
		EnableDurationMeta: true,
	}
}
