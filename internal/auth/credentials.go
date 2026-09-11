package auth

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
)

// AllBuckets is the wildcard that scopes a credential to every bucket.
const AllBuckets = "*"

// Client is one set of credentials the proxy accepts.
//
// These are the proxy's own credentials, unrelated to the ones it uses upstream.
// A client never learns the upstream credentials, which is what stops it
// bypassing the gateway and reading ciphertext directly -- or writing plaintext.
type Client struct {
	Name            string
	AccessKeyID     string
	SecretAccessKey string
	// Buckets lists the buckets this credential may use. "*" means all.
	Buckets []string
}

// LogValue keeps the secret out of logs even when a Client is logged whole.
func (c Client) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", c.Name),
		slog.String("access_key_id", c.AccessKeyID),
		slog.Any("buckets", c.Buckets),
	)
}

// MayAccess reports whether this credential is scoped to bucket.
func (c Client) MayAccess(bucket string) bool {
	for _, allowed := range c.Buckets {
		if allowed == AllBuckets || allowed == bucket {
			return true
		}
	}
	return false
}

// Registry holds the configured client credentials.
type Registry struct {
	byKeyID map[string]Client
}

// NewRegistry validates and indexes a set of clients.
func NewRegistry(clients []Client) (*Registry, error) {
	if len(clients) == 0 {
		return nil, fmt.Errorf("auth: at least one client credential is required")
	}

	byKeyID := make(map[string]Client, len(clients))
	for _, c := range clients {
		switch {
		case c.AccessKeyID == "":
			return nil, fmt.Errorf("auth: client %q has no access key id", c.Name)
		case c.SecretAccessKey == "":
			return nil, fmt.Errorf("auth: client %q has no secret access key", c.Name)
		case len(c.Buckets) == 0:
			// An empty list would silently deny everything, which looks like a
			// broken proxy rather than a configuration mistake.
			return nil, fmt.Errorf("auth: client %q lists no buckets (use %q for all)",
				c.Name, AllBuckets)
		}
		if _, exists := byKeyID[c.AccessKeyID]; exists {
			return nil, fmt.Errorf("auth: access key id %q is used by more than one client", c.AccessKeyID)
		}
		byKeyID[c.AccessKeyID] = c
	}
	return &Registry{byKeyID: byKeyID}, nil
}

// lookup finds a client by access key id in constant time with respect to the
// secret, and reports whether it exists.
func (r *Registry) lookup(accessKeyID string) (Client, bool) {
	c, ok := r.byKeyID[accessKeyID]
	return c, ok
}

// equalSignature compares two hex signatures without leaking where they differ.
func equalSignature(a, b string) bool {
	if len(a) != len(b) {
		// The lengths are both checked against the fixed hex width earlier, so
		// this is not a timing signal about the secret.
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
