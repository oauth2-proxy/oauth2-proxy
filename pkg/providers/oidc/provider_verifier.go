package oidc

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"io/ioutil"
	k8serrors "k8s.io/apimachinery/pkg/util/errors"
)

// ProviderVerifier represents the OIDC discovery and verification process
type ProviderVerifier interface {
	DiscoveryEnabled() bool
	Provider() DiscoveryProvider
	Verifier() IDTokenVerifier
}

// ProviderVerifierOptions allows you to configure a ProviderVerifier
type ProviderVerifierOptions struct {
	// AudienceClaim allows to define any claim that is verified against the client id
	// By default `aud` claim is used for verification.
	AudienceClaims []string

	// ClientID is the OAuth Client ID that is defined in the provider
	ClientID string

	// ExtraAudiences is a list of additional audiences that are allowed
	// to pass verification in addition to the client id.
	ExtraAudiences []string

	// IssuerURL is the OpenID Connect issuer URL
	// eg: https://accounts.google.com
	IssuerURL string

	// JWKsURL is the OpenID Connect JWKS URL
	// eg: https://www.googleapis.com/oauth2/v3/certs
	JWKsURL string

	// TODO:
	PublicKeys []string

	// SkipDiscovery allows to skip OIDC discovery and use manually supplied Endpoints
	SkipDiscovery bool

	// SkipIssuerVerification skips verification of ID token issuers.
	// When false, ID Token Issuers must match the OIDC discovery URL.
	SkipIssuerVerification bool

	// SupportedSigningAlgs is the list of signature algorithms supported by the
	// provider.
	SupportedSigningAlgs []string
}

// validate checks that the required options are present before attempting to create
// the ProviderVerifier.
func (p ProviderVerifierOptions) validate() error {
	var errs []error

	if p.IssuerURL == "" {
		errs = append(errs, errors.New("missing required setting: issuer-url"))
	}

	if p.SkipDiscovery && p.JWKsURL == "" && len(p.PublicKeys) == 0 {
		errs = append(errs, errors.New("missing required setting: jwks-url or public-keys"))
	}

	if p.JWKsURL != "" && len(p.PublicKeys) > 0 {
		errs = append(errs, errors.New("mutually exclusive settings: jwks-url and public-keys"))
	}

	if len(errs) > 0 {
		return k8serrors.NewAggregate(errs)
	}
	return nil
}

// toVerificationOptions returns an IDTokenVerificationOptions based on the configured options.
func (p ProviderVerifierOptions) toVerificationOptions() IDTokenVerificationOptions {
	return IDTokenVerificationOptions{
		AudienceClaims: p.AudienceClaims,
		ClientID:       p.ClientID,
		ExtraAudiences: p.ExtraAudiences,
	}
}

// toOIDCConfig returns an oidc.Config based on the configured options.
func (p ProviderVerifierOptions) toOIDCConfig() *oidc.Config {
	return &oidc.Config{
		ClientID:             p.ClientID,
		SkipIssuerCheck:      p.SkipIssuerVerification,
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: p.SupportedSigningAlgs,
	}
}

// NewProviderVerifier constructs a ProviderVerifier from the options given.
func NewProviderVerifier(ctx context.Context, opts ProviderVerifierOptions) (ProviderVerifier, error) {
	if err := opts.validate(); err != nil {
		return nil, fmt.Errorf("invalid provider verifier options: %v", err)
	}

	verifierBuilder, provider, err := getVerifierBuilder(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("could not get verifier builder: %v", err)
	}
	verifier := NewVerifier(verifierBuilder(opts.toOIDCConfig()), opts.toVerificationOptions())

	if provider == nil {
		// To avoid the possibility of nil pointers, always return an empty provider if discovery didn't occur.
		// Users are expected to check whether discovery was enabled before using the provider.
		provider = &discoveryProvider{}
	}

	return &providerVerifier{
		discoveryEnabled: !opts.SkipDiscovery,
		provider:         provider,
		verifier:         verifier,
	}, nil
}

type verifierBuilder func(*oidc.Config) *oidc.IDTokenVerifier

func getVerifierBuilder(ctx context.Context, opts ProviderVerifierOptions) (verifierBuilder, DiscoveryProvider, error) {
	if opts.SkipDiscovery {
		var keySet oidc.KeySet
		if opts.JWKsURL != "" {
			keySet = oidc.NewRemoteKeySet(ctx, opts.JWKsURL)
		} else {
			_keySet, err := newKeySetFromStatic(opts.PublicKeys)
			if err != nil {
				return nil, nil, fmt.Errorf("error while parsing public keys: %v", err)
			}
			keySet = _keySet
		}
		// Instead of discovering the JWKs URK, it needs to be specified in the opts already
		return newVerifierBuilder(
			opts.IssuerURL,
			keySet,
			opts.SupportedSigningAlgs,
		), nil, nil
	}

	provider, err := NewProvider(ctx, opts.IssuerURL, opts.SkipIssuerVerification)
	if err != nil {
		return nil, nil, fmt.Errorf("error while discovery OIDC configuration: %v", err)
	}
	verifierBuilder := newVerifierBuilder(opts.IssuerURL, oidc.NewRemoteKeySet(ctx, provider.Endpoints().JWKsURL), provider.SupportedSigningAlgs())
	return verifierBuilder, provider, nil
}

// ReadFile reads the contents of a file into a byte array.
func ReadFile(filename string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return bytes, nil
}

// GetPublicKeyFromBytes parses a PEM-encoded public key from a byte array
// and returns a crypto.PublicKey object.
func GetPublicKeyFromBytes(bytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	cryptoPublicKey, ok := publicKey.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to cast public key to crypto.PublicKey")
	}

	return cryptoPublicKey, nil
}

// newKeySetFromStatic create a StaticKeySet from a set of files
func newKeySetFromStatic(keys []string) (*oidc.StaticKeySet, error) {
	var keySet []crypto.PublicKey
	for _, keyFile := range keys {
		bytes, err := ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		publicKey, err := GetPublicKeyFromBytes(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create keys: %w", err)
		}
		keySet = append(keySet, publicKey)
	}

	return &oidc.StaticKeySet{PublicKeys: keySet}, nil
}

// newVerifierBuilder returns a function to create a IDToken verifier from an OIDC config.
func newVerifierBuilder(issuerURL string, keySet oidc.KeySet, supportedSigningAlgs []string) verifierBuilder {
	return func(oidcConfig *oidc.Config) *oidc.IDTokenVerifier {
		if len(supportedSigningAlgs) > 0 {
			oidcConfig.SupportedSigningAlgs = supportedSigningAlgs
		}

		return oidc.NewVerifier(issuerURL, keySet, oidcConfig)
	}
}

// providerVerifier is an implementation of the ProviderVerifier interface
type providerVerifier struct {
	discoveryEnabled bool
	provider         DiscoveryProvider
	verifier         IDTokenVerifier
}

// DiscoveryEnabled returns whether the provider verifier was constructed
// using the OIDC discovery process or whether it was manually discovered.
func (p *providerVerifier) DiscoveryEnabled() bool {
	return p.discoveryEnabled
}

// Provider returns the OIDC discovery provider
func (p *providerVerifier) Provider() DiscoveryProvider {
	return p.provider
}

// Verifier returns the ID token verifier
func (p *providerVerifier) Verifier() IDTokenVerifier {
	return p.verifier
}
