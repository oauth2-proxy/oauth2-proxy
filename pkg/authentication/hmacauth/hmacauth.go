package hmacauth

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

// HmacAuth signs outbound requests and authenticates inbound requests.
type HmacAuth interface {
	// Produces the string that will be prefixed to the request body and
	// used to generate the signature.
	StringToSign(req *http.Request) string

	// Adds a signature header to the request.
	SignRequest(req *http.Request)

	// Generates a signature for the request.
	RequestSignature(req *http.Request) string

	// Retrieves the signature included in the request header.
	SignatureFromHeader(req *http.Request) string

	// Authenticates the request, returning the result code, the signature
	// from the header, and the locally-computed signature.
	AuthenticateRequest(request *http.Request) (
		result AuthenticationResult,
		headerSignature, computedSignature string)
}

var supportedAlgorithms = map[string]crypto.Hash{
	"md4":       crypto.MD4,
	"md5":       crypto.MD5,
	"sha1":      crypto.SHA1,
	"sha224":    crypto.SHA224,
	"sha256":    crypto.SHA256,
	"sha384":    crypto.SHA384,
	"sha512":    crypto.SHA512,
	"ripemd160": crypto.RIPEMD160,
}

var algorithmName map[crypto.Hash]string

func init() {
	algorithmName = make(map[crypto.Hash]string)
	for name, algorithm := range supportedAlgorithms {
		algorithmName[algorithm] = name
		// Make sure the algorithm is linked into the binary, per
		// https://golang.org/pkg/crypto/#Hash.Available
		//
		// Note that both sides of the client/server connection must
		// have an algorithm available in order to successfully
		// authenticate using that algorithm
		if algorithm.Available() == false {
			delete(supportedAlgorithms, name)
		}
	}
}

// DigestNameToCryptoHash returns the crypto.Hash value corresponding to the
// algorithm name, or an error if the algorithm is not supported.
func DigestNameToCryptoHash(name string) (result crypto.Hash, err error) {
	var supported bool
	if result, supported = supportedAlgorithms[name]; !supported {
		err = errors.New("hmacauth: hash algorithm not supported: " +
			name)
	}
	return
}

// CryptoHashToDigestName returns the algorithm name corresponding to the
// crypto.Hash ID, or an error if the algorithm is not supported.
func CryptoHashToDigestName(id crypto.Hash) (result string, err error) {
	var supported bool
	if result, supported = algorithmName[id]; !supported {
		err = errors.New("hmacauth: unsupported crypto.Hash #" +
			strconv.Itoa(int(id)))
	}
	return
}

type hmacAuth struct {
	hash    crypto.Hash
	key     []byte
	header  string
	headers []string
}

// NewHmacAuth returns an HmacAuth object that can be used to sign or
// authenticate HTTP requests based on the supplied parameters.
func NewHmacAuth(hash crypto.Hash, key []byte, header string,
	headers []string) HmacAuth {
	if hash.Available() == false {
		var name string
		var supported bool
		if name, supported = algorithmName[hash]; !supported {
			name = "#" + strconv.Itoa(int(hash))
		}
		panic("hmacauth: hash algorithm " + name + " is unavailable")
	}
	canonicalHeaders := make([]string, len(headers))
	for i, h := range headers {
		canonicalHeaders[i] = http.CanonicalHeaderKey(h)
	}
	return &hmacAuth{hash, key, header, canonicalHeaders}
}

func (auth *hmacAuth) StringToSign(req *http.Request) string {
	var buffer bytes.Buffer
	_, _ = buffer.WriteString(req.Method)
	_, _ = buffer.WriteString("\n")

	for _, header := range auth.headers {
		values := req.Header[header]
		lastIndex := len(values) - 1
		for i, value := range values {
			_, _ = buffer.WriteString(value)
			if i != lastIndex {
				_, _ = buffer.WriteString(",")
			}
		}
		_, _ = buffer.WriteString("\n")
	}
	_, _ = buffer.WriteString(req.URL.Path)
	if req.URL.RawQuery != "" {
		_, _ = buffer.WriteString("?")
		_, _ = buffer.WriteString(req.URL.RawQuery)
	}
	if req.URL.Fragment != "" {
		_, _ = buffer.WriteString("#")
		_, _ = buffer.WriteString(req.URL.Fragment)
	}
	_, _ = buffer.WriteString("\n")
	return buffer.String()
}

func (auth *hmacAuth) SignRequest(req *http.Request) {
	req.Header.Set(auth.header, auth.RequestSignature(req))
}

func (auth *hmacAuth) RequestSignature(req *http.Request) string {
	return requestSignature(auth, req, auth.hash)
}

func requestSignature(auth *hmacAuth, req *http.Request,
	hashAlgorithm crypto.Hash) string {
	h := hmac.New(hashAlgorithm.New, auth.key)
	_, _ = h.Write([]byte(auth.StringToSign(req)))

	if req.Body != nil {
		reqBody, _ := ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))
		_, _ = h.Write(reqBody)
	}

	var sig []byte
	sig = h.Sum(sig)
	return algorithmName[hashAlgorithm] + " " +
		base64.StdEncoding.EncodeToString(sig)
}

func (auth *hmacAuth) SignatureFromHeader(req *http.Request) string {
	return req.Header.Get(auth.header)
}

// AuthenticationResult is a code used to identify the outcome of
// HmacAuth.AuthenticateRequest().
type AuthenticationResult int

const (
	// ResultNoSignature - the incoming result did not have a signature
	// header.
	ResultNoSignature AuthenticationResult = iota

	// ResultInvalidFormat - the signature header was not parseable.
	ResultInvalidFormat

	// ResultUnsupportedAlgorithm - the signature header specified an
	// unsupported algorithm.
	ResultUnsupportedAlgorithm

	// ResultMatch - the signature from the request header matched the
	// locally-computed signature.
	ResultMatch

	// ResultMismatch - the signature from the request header did not match
	// the locally-computed signature.
	ResultMismatch
)

var validationResultStrings = []string{
	"",
	"ResultNoSignature",
	"ResultInvalidFormat",
	"ResultUnsupportedAlgorithm",
	"ResultMatch",
	"ResultMismatch",
}

func (result AuthenticationResult) String() string {
	return validationResultStrings[result]
}

func (auth *hmacAuth) AuthenticateRequest(request *http.Request) (
	result AuthenticationResult, headerSignature,
	computedSignature string) {
	headerSignature = auth.SignatureFromHeader(request)
	if headerSignature == "" {
		result = ResultNoSignature
		return
	}

	components := strings.Split(headerSignature, " ")
	if len(components) != 2 {
		result = ResultInvalidFormat
		return
	}

	algorithm, err := DigestNameToCryptoHash(components[0])
	if err != nil {
		result = ResultUnsupportedAlgorithm
		return
	}

	computedSignature = requestSignature(auth, request, algorithm)
	if hmac.Equal([]byte(headerSignature), []byte(computedSignature)) {
		result = ResultMatch
	} else {
		result = ResultMismatch
	}
	return
}
