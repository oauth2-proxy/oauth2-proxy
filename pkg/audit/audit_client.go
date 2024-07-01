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

func (a *Client) CreateSuccessfulLoginAuditEntry(ss *sessions.SessionState, appURL string, tenantId string) {
	a.createAuditEntry(ss, appURL, tenantId, "0", "Success")
}

func (a *Client) CreateFailedLoginAuditEntry(ss *sessions.SessionState, appURL string, tenantId string, errorDesc string) {
	a.createAuditEntry(ss, appURL, tenantId, "1", errorDesc)
}

func (a *Client) createAuditEntry(ss *sessions.SessionState, appURL string, tenantId string, outcomeCode string, outcomeDesc string) {
	if !a.enabled {
		return
	}
	auditObject := AuditEvent{
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
					System:  "http://hl7.org/fhir/ValueSet/identifier-type",
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
							ValueString: a.opts.ProductName,
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
							ValueString: a.opts.ProductKey,
						},
						{
							URL:         "tenant",
							ValueString: tenantId,
						},
					},
				},
			},
		},
	}

	auditMessage, err := json.Marshal(auditObject)
	if err != nil {
		logger.Errorf("%s: could not marshal the audit object: %v", ErrPersitAuditEvent.Error(), err)
		return
	}
	err = a.send(string(auditMessage))
	if err != nil {
		logger.Errorf("%s: could not send the audit message to the url '%s': %v", ErrPersitAuditEvent.Error(), a.opts.URL, err)
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

func (a *ClientOpts) Validate() error {
	if strings.TrimSpace(a.ProductName) == "" || strings.TrimSpace(a.ProductKey) == "" || strings.TrimSpace(a.SecretKey) == "" || strings.TrimSpace(a.SharedKey) == "" {
		return errors.New("the audit is enabled and therefore the audit product name, audit key, audit secret key or audit shared key are required (however found empty)")
	}
	return nil
}
