package healthcheck

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

func PerformHealthcheck(opts *options.Options) error {
	var errs = make([]error, 0)

	if opts.Server.BindAddress != "" && opts.Server.BindAddress != "-" {
		errs = append(errs, performHealthcheckWithScheme("http", opts.Server.BindAddress, opts.PingPath))
	}
	if opts.Server.SecureBindAddress != "" && opts.Server.SecureBindAddress != "-" {
		errs = append(errs, performHealthcheckWithScheme("https", opts.Server.SecureBindAddress, opts.PingPath))
	}

	return errors.Join(errs...)
}

func performHealthcheckWithScheme(scheme string, addr string, path string) error {
	url, err := getHealthcheckURL(scheme, addr, path)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	res, err := requests.DefaultHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return checkHealthcheckResponse(res)
}

func getHealthcheckURL(scheme string, addr string, path string) (string, error) {
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("ping-path must be non-empty and start with '/'")
	}

	i := strings.Index(addr, "://")
	if i > -1 {
		scheme, addr = addr[:i], addr[i+1:]
	}

	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("only http and https schemes supported for healthcheck, not %v", scheme)
	}

	i = strings.LastIndex(addr, ":")
	if i < 0 {
		return "", fmt.Errorf("no port delimiter (':') in %v", addr)
	}

	host, port := addr[:i], addr[i+1:]
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "[::]" {
		host = "[::1]"
	}

	return fmt.Sprintf("%s://%s:%s%s", scheme, host, port, path), nil
}

func checkHealthcheckResponse(res *http.Response) error {
	if res.StatusCode != 200 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("url %v, status %v, body %q", res.Request.URL, res.StatusCode, body)
	}

	return nil
}
