// Copyright (c) 2022 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package go_oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Jing-ze/oauth2-proxy/pkg/util"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/go-jose/go-jose/v4"
)

// StaticKeySet is a verifier that validates JWT against a static set of public keys.
type StaticKeySet struct {
	// PublicKeys used to verify the JWT. Supported types are *rsa.PublicKey and
	// *ecdsa.PublicKey.
	PublicKeys []crypto.PublicKey
}

// VerifySignature compares the signature against a static set of public keys.
func (s *StaticKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	// Algorithms are already checked by Verifier, so this parse method accepts
	// any algorithm.
	jws, err := jose.ParseSigned(jwt, allAlgs)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %v", err)
	}
	for _, pub := range s.PublicKeys {
		switch pub.(type) {
		case *rsa.PublicKey:
		case *ecdsa.PublicKey:
		case ed25519.PublicKey:
		default:
			return nil, fmt.Errorf("invalid public key type provided: %T", pub)
		}
		payload, err := jws.Verify(pub)
		if err != nil {
			continue
		}
		return payload, nil
	}
	return nil, fmt.Errorf("no public keys able to verify jwt")
}

// NewRemoteKeySet returns a KeySet that can validate JSON web tokens by using HTTP
// GETs to fetch JSON web token sets hosted at a remote URL. This is automatically
// used by NewProvider using the URLs returned by OpenID Connect discovery, but is
// exposed for providers that don't support discovery or to prevent round trips to the
// discovery URL.
//
// The returned KeySet is a long lived verifier that caches keys based on any
// keys change. Reuse a common remote key set instead of creating new ones as needed.
func NewRemoteKeySet(ctx context.Context, jwksURL string) *RemoteKeySet {
	return newRemoteKeySet(ctx, jwksURL, time.Now)
}

func newRemoteKeySet(ctx context.Context, jwksURL string, now func() time.Time) *RemoteKeySet {
	if now == nil {
		now = time.Now
	}
	return &RemoteKeySet{jwksURL: jwksURL, ctx: ctx, now: now}
}

// RemoteKeySet is a KeySet implementation that validates JSON web tokens against
// a jwks_uri endpoint.
type RemoteKeySet struct {
	jwksURL string
	ctx     context.Context
	now     func() time.Time

	// A set of cached keys.
	cachedKeys []jose.JSONWebKey
}

// paresdJWTKey is a context key that allows common setups to avoid parsing the
// JWT twice. It holds a *jose.JSONWebSignature value.
var parsedJWTKey int

// VerifySignature validates a payload against a signature from the jwks_uri.
//
// Users MUST NOT call this method directly and should use an IDTokenVerifier
// instead. This method skips critical validations such as 'alg' values and is
// only exported to implement the KeySet interface.
func (r *RemoteKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, ok := ctx.Value(parsedJWTKey).(*jose.JSONWebSignature)
	if !ok {
		// The algorithm values are already enforced by the Validator, which also sets
		// the context value above to pre-parsed signature.
		//
		// Practically, this codepath isn't called in normal use of this package, but
		// if it is, the algorithms have already been checked.
		var err error
		jws, err = jose.ParseSigned(jwt, allAlgs)
		if err != nil {
			return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
		}
	}
	return r.verify(jws)
}

func (r *RemoteKeySet) verify(jws *jose.JSONWebSignature) ([]byte, error) {
	// We don't support JWTs signed with multiple signatures.
	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}

	keys := r.keysFromCache()
	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}
	return nil, errors.New("failed to verify id token signature")
}

func (r *RemoteKeySet) keysFromCache() (keys []jose.JSONWebKey) {
	return r.cachedKeys
}

func (r *RemoteKeySet) UpdateKeys(client wrapper.HttpClient, timeout uint32, callback func(args ...interface{})) error {
	var keySet jose.JSONWebKeySet
	client.Get(r.jwksURL, nil, func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		if statusCode != http.StatusOK {
			util.Logger.Errorf("RemoteKeySet UpdateKeys http call failed, status: %d", statusCode)
			return
		}
		json.Unmarshal(responseBody, &keySet)
		r.cachedKeys = keySet.Keys
		callback(true)
	}, timeout)
	return nil
}
