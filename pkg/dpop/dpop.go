package dpop

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

// claims represents the expected payload claims of a DPoP proof.
type claims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath,omitempty"`
}

// CalcATH calculates the base64url encoded SHA-256 hash of an access token
// to be used as the `ath` claim in a DPoP proof.
func CalcATH(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// Validator is an interface for validating DPoP proofs.
type Validator interface {
	ValidateDPopToken(req *http.Request, accessToken string) (string, error)
}

type dpopValidator struct {
	timeWindow time.Duration
	store      DpopStore
}

// NewDpopValidator creates a new DPoP validator with the given configuration.
func NewDpopValidator(timeWindow time.Duration, store DpopStore) Validator {
	return &dpopValidator{
		timeWindow: timeWindow,
		store:      store,
	}
}

// ValidateDPopToken validates the DPoP proof in the HTTP headers based on RFC 9449 (https://datatracker.ietf.org/doc/html/rfc9449#name-checking-dpop-proofs).
// It implements the DPoP proof validation steps described in Section 4.3.
// Returns the JWK thumbprint on success, or an error if validation fails.
//
// Note: If an opaque access token is used, the caller is responsible for extracting
// and verifying the JKT (e.g., via introspection) against the returned thumbprint.
func (v *dpopValidator) ValidateDPopToken(req *http.Request, token string) (string, error) {
	dpopJws, err := parseDpopHeaderJws(req)
	if err != nil {
		return "", err
	}

	dpopPayload, dpopJwk, err := checkJwsSignature(dpopJws)
	if err != nil {
		return "", err
	}

	claims, err := parseAndCheckDpopClaims(dpopPayload, req, v.timeWindow)
	if err != nil {
		return "", err
	}

	dpopJkt, err := calculateJkt(dpopJwk)
	if err != nil {
		return "", err
	}

	if token != "" {
		if err := checkTokenAgainstJwtAth(token, claims); err != nil {
			return "", err
		}
		if tokenCnfJkt := extractJwtCnfJktClaim(token); tokenCnfJkt != "" {
			if tokenCnfJkt != dpopJkt {
				return "", fmt.Errorf("DPoP thumbprint mismatch: token jkt %q != DPoP proof jkt %q", tokenCnfJkt, dpopJkt)
			}
		}
	}

	if v.store != nil {
		if err := v.checkJwtReplay(req.Context(), dpopJkt, claims); err != nil {
			return "", err
		}
	}

	return dpopJkt, nil
}

// parseDpopHeaderJws parses the DPoP header string into a JSON Web Signature.
// It enforces the requirement of a single DPoP header per RFC 9449 Section 4.1 (https://datatracker.ietf.org/doc/html/rfc9449#name-the-dpop-http-header).
// Returns an error if multiple DPoP headers are present or the header is empty/invalid.
func parseDpopHeaderJws(req *http.Request) (*jose.JSONWebSignature, error) {
	dpopHeaders := req.Header.Values("DPoP")
	if len(dpopHeaders) == 0 {
		return nil, errors.New("missing DPoP header")
	}
	if len(dpopHeaders) > 1 {
		return nil, errors.New("multiple DPoP headers present")
	}

	dpopJws, err := jose.ParseSigned(dpopHeaders[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse DPoP JWS: %v", err)
	}

	return dpopJws, nil
}

// checkJwsSignature checks the JWS signature using the embedded JWK.
// It validates the `typ` and `alg` headers and verifies the signature per RFC 9449 (https://datatracker.ietf.org/doc/html/rfc9449#name-checking-dpop-proofs).
func checkJwsSignature(dpopJws *jose.JSONWebSignature) ([]byte, *jose.JSONWebKey, error) {
	if len(dpopJws.Signatures) != 1 {
		return nil, nil, errors.New("expected exactly one signature in DPoP JWS")
	}

	sig := dpopJws.Signatures[0]
	header := sig.Protected

	// RFC 9449 Section 4.2: typ must be "dpop+jwt"
	typ, ok := header.ExtraHeaders["typ"].(string)
	if !ok || !strings.EqualFold(typ, "dpop+jwt") {
		return nil, nil, errors.New("invalid or missing typ header claim, expected dpop+jwt")
	}

	// alg must not be "none" (go-jose rejects empty alg, but explicitly check for none)
	if header.Algorithm == "none" || header.Algorithm == "" {
		return nil, nil, errors.New("invalid alg header claim")
	}

	// JWK must be present
	jwk := header.JSONWebKey
	if jwk == nil {
		return nil, nil, errors.New("missing jwk header claim")
	}
	if !jwk.Valid() {
		return nil, nil, errors.New("invalid jwk header claim")
	}

	// Verify the signature
	payload, err := dpopJws.Verify(jwk)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify DPoP signature: %v", err)
	}

	return payload, jwk, nil
}

// parseAndCheckDpopClaims parses the payload and validates the required DPoP claims.
// It verifies htm, htu, jti, and iat per RFC 9449 Section 4.3.
func parseAndCheckDpopClaims(payloadBytes []byte, req *http.Request, timeWindow time.Duration) (*claims, error) {
	var claims claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DPoP payload: %v", err)
	}

	// jti is required
	if claims.JTI == "" {
		return nil, errors.New("missing jti claim")
	}

	// htm must match the HTTP method
	if !strings.EqualFold(claims.HTM, req.Method) {
		return nil, fmt.Errorf("htm claim (%q) does not match HTTP method (%q)", claims.HTM, req.Method)
	}

	// htu must match the HTTP URI (excluding query and fragment)
	// Construct absolute URL from request
	scheme := util.GetRequestProto(req)
	host := util.GetRequestHost(req)
	path := util.GetRequestPath(req)
	expectedHTU := fmt.Sprintf("%s://%s%s", scheme, host, path)

	if !strings.EqualFold(claims.HTU, expectedHTU) {
		return nil, fmt.Errorf("htu claim (%q) does not match expected URI (%q)", claims.HTU, expectedHTU)
	}

	if claims.IAT == 0 {
		return nil, errors.New("missing iat claim")
	}

	// iat must be within an acceptable time window
	iatTime := time.Unix(claims.IAT, 0)
	now := time.Now()
	if iatTime.Before(now.Add(-timeWindow)) || iatTime.After(now.Add(timeWindow)) {
		return nil, fmt.Errorf("invalid iat claim: %v is outside acceptable window", iatTime)
	}

	return &claims, nil
}

// calculateJkt calculates the JWK Thumbprint (RFC 7638) using SHA-256 (https://datatracker.ietf.org/doc/html/rfc7638).
func calculateJkt(jwk *jose.JSONWebKey) (string, error) {
	dpopThumbprintBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to calculate JWK thumbprint: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(dpopThumbprintBytes), nil
}

// checkTokenAgainstJwtAth validates the ath claim against the access token per RFC 9449 Section 4.3.
func checkTokenAgainstJwtAth(accessToken string, claims *claims) error {
	// ath must match the base64url encoding of the SHA-256 hash of the access token
	if claims.ATH == "" {
		return errors.New("missing ath claim, required when access token is used")
	}
	expectedATH := CalcATH(accessToken)
	if claims.ATH != expectedATH {
		return fmt.Errorf("ath claim (%q) does not match access token hash (%q)", claims.ATH, expectedATH)
	}
	return nil
}

// dpopTokenClaims defines the expected structure of a DPoP-bound access token.
type dpopTokenClaims struct {
	jwt.RegisteredClaims
	Cnf struct {
		Jkt string `json:"jkt"`
	} `json:"cnf"`
}

func extractJwtCnfJktClaim(tokenString string) string {
	var claims dpopTokenClaims
	// If it fails to parse as a JWT, we assume it's an opaque token where
	// cnf binding must be validated downstream by an introspection endpoint.
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, &claims); err != nil {
		return ""
	}
	return claims.Cnf.Jkt
}

func (v *dpopValidator) checkJwtReplay(ctx context.Context, jkt string, claims *claims) error {
	iatTime := time.Unix(claims.IAT, 0)
	if added, err := v.store.MarkJtiSeen(ctx, jkt, claims.JTI, iatTime.Add(v.timeWindow*2)); err != nil {
		return fmt.Errorf("failed to check JTI replay status: %v", err)
	} else if !added {
		return errors.New("invalid DPoP proof: jti has already been used (replay attack)")
	}
	return nil
}
