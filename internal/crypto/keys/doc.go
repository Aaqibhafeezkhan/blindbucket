// Package keys handles data encryption keys: generation, wrapping under a
// key-encryption key, the keyring holding several KEK versions, and the KeyProvider
// implementations that unlock it (file, Vault Transit, AWS KMS).
//
// See docs/adr/ADR-002-key-hierarchy.md.
package keys
