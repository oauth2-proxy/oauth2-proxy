package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

type ClientOpts struct {
	Enabled     bool
	URL         string
	ProductKey  string
	ProductName string
	SharedKey   string
	SecretKey   string
}

// Client interface for communicating with audit system
type Client struct {
	enabled      bool
	apiSignature APISignature
	opts         *ClientOpts
	client       *resty.Client
}

func NewAuditClient(opts *ClientOpts) (*Client, error) {
	if opts.Enabled {
		log.Print("Audit entries will be created since OAUTH2_PROXY_ENABLE_AUDIT is true")
		err := opts.Validate()
		if err != nil {
			return nil, err
		}
	} else {
		log.Print("Audit entries will NOT be created since OAUTH2_PROXY_ENABLE_AUDIT is false")
	}
	apiSignature := NewAPISignature(opts.SecretKey, opts.SharedKey)
	client := resty.New()
	client.SetRetryCount(3).
		SetRetryWaitTime(5 * time.Second).
		SetRetryMaxWaitTime(20 * time.Second).
		SetContentLength(true).
		SetRetryAfter(func(client *resty.Client, resp *resty.Response) (time.Duration, error) {
			return 0, fmt.Errorf("%w: retry quota exceeded", ErrPersitAuditEvent)
		})
	return &Client{enabled: opts.Enabled, apiSignature: apiSignature, client: client, opts: opts}, nil
}

func (c *Client) CreateSuccessfulLoginAuditEntry(ss *sessions.SessionState, appURL string, tenantID string) {
	c.createAuditEntry(ss, appURL, tenantID, "0", "Success")
}

func (c *Client) CreateFailedLoginAuditEntry(ss *sessions.SessionState, appURL string, tenantID string, errorDesc string) {
	c.createAuditEntry(ss, appURL, tenantID, "1", errorDesc)
}

func (c *Client) createAuditEntry(ss *sessions.SessionState, appURL string, tenantID string, outcomeCode string, outcomeDesc string) {
	if !c.enabled {
		return
	}
	auditObject := RootEvent{
		ResourceType: "AuditEvent",
		Event: &Event{
			Type: &Coding{
				System: "http://hl7.org/fhir/ValueSet/audit-event-type", Version: "1", Code: "110114", Display: "User Authentication"},
			Action:      "E",
			DateTime:    time.Now().UTC().Format(time.RFC3339),
			Outcome:     outcomeCode,
			OutcomeDesc: outcomeDesc},

		Participant: []*Participant{
			{AltID: ss.User, UserID: UserID{Value: ss.Email}, Name: ss.PreferredUsername, Requestor: true}},
		Source: Source{
			Identifier: Identifier{
				Type: &Coding{
					System:  "http://hl7.org/fhir/ValueSet/audit-source-type",
					Code:    "4",
					Display: "Application Server",
				},
				Value: ss.Email,
			},
			Type: []*Coding{{System: "http://hl7.org/fhir/security-source-type", Code: "1", Display: "End-user display device, diagnostic device."}},
			Extension: []*Extension{
				{
					URL: appURL,
					Extension: []*ExtensionContent{
						{
							URL:         "applicationName",
							ValueString: c.opts.ProductName,
						},
						{
							URL:         "applicationVersion",
							ValueString: "1",
						},
						{
							URL:         "serverName",
							ValueString: "oauth2proxy",
						},
						{
							URL:         "componentName",
							ValueString: "oauth2proxy",
						},
						{
							URL:         "productKey",
							ValueString: c.opts.ProductKey,
						},
						{
							URL:         "tenant",
							ValueString: tenantID,
						},
					},
				},
			},
		},
	}

	auditMessage, err := json.Marshal(auditObject)
	if err != nil {
		logger.Errorf("%s: could not marshal the audit object: %v", ErrPersitAuditEvent.Error(), err)
		AuditErrorMetricCounter.Inc()
		return
	}
	err = c.send(string(auditMessage))
	if err != nil {
		logger.Errorf("%s: could not send the audit message to the url '%s': %v", ErrPersitAuditEvent.Error(), c.opts.URL, err)
		AuditErrorMetricCounter.Inc()
		return
	}
}

func (c *Client) send(msg string) error {
	signedDate := time.Now().UTC().Format(time.RFC3339)
	signature := c.apiSignature.GetSignature(signedDate)
	resp, err := c.client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("api-version", "2").
		SetHeader("HSDP-API-Signature", signature).
		SetHeader("SignedDate", signedDate).
		SetBody(msg).
		Post(c.opts.URL)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 201 {
		log.Println("Not able to send the audit message ", resp)
		return fmt.Errorf("not able to persist audit, audit server returned %v", resp.StatusCode())
	}
	return nil
}

func (c *ClientOpts) Validate() error {
	err := errors.New("")
	if strings.TrimSpace(c.URL) == "" {
		err = errors.New("the OAUTH2_PROXY_AUDIT_URL must be set")
	}

	if strings.TrimSpace(c.ProductName) == "" {
		err = fmt.Errorf("%w: the OAUTH2_PROXY_AUDIT_PRODUCT_NAME must be set", err)
	}

	if strings.TrimSpace(c.ProductKey) == "" {
		err = fmt.Errorf("%w: the OAUTH2_PROXY_AUDIT_PRODUCT_KEY must be set", err)
	}

	if strings.TrimSpace(c.SharedKey) == "" {
		err = fmt.Errorf("%w: the OAUTH2_PROXY_AUDIT_SHARED_KEY must be set", err)
	}

	if strings.TrimSpace(c.SecretKey) == "" {
		err = fmt.Errorf("%w: the OAUTH2_PROXY_AUDIT_SECRET_KEY must be set", err)
	}

	if err != nil && err.Error() != "" {
		return fmt.Errorf("the OAUTH2_PROXY_ENABLE_AUDIT is set to true however these are missing: %w", err)
	}
	return nil
}
