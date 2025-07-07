package audit

type Coding struct {
	System  string `json:"system,omitempty"`
	Version string `json:"version,omitempty"`
	Code    string `json:"code,omitempty"`
	Display string `json:"display,omitempty"`
	// AuditServer is complaining about UserSelected. Do not use.
	UserSelected string `json:"userSelected,omitempty"`
}

type Identifier struct {
	Use    string  `json:"use,omitempty"`
	Type   *Coding `json:"type,omitempty"`
	Value  string  `json:"value,omitempty"`
	System string  `json:"system,omitempty"`
}

type Reference struct {
	Reference string `json:"reference,omitempty"`
	Display   string `json:"display,omitempty"`
}

type Detail struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

type Object struct {
	Identifier    *Identifier `json:"identifier,omitempty"`
	Reference     *Reference  `json:"reference,omitempty"`
	Type          *Coding     `json:"type,omitempty"`
	Role          *Coding     `json:"role,omitempty"`
	Lifecycle     *Coding     `json:"lifecycle,omitempty"`
	SecurityLabel []Coding    `json:"securityLabel,omitempty"`
	Description   string      `json:"description,omitempty"`
	Query         interface{} `json:"query,omitempty"`
	Name          string      `json:"name,omitempty"`
	Detail        []Detail    `json:"detail,omitempty"`
}

type Type struct {
	Coding `json:"coding,omitempty"`
	Text   string `json:"text,omitempty"`
}

type UserID struct {
	Use    string `json:"use,omitempty"`
	Type   *Type  `json:"type,omitempty"`
	System string `json:"system,omitempty"`
	Value  string `json:"value,omitempty"`
}

type Network struct {
	Address string `json:"address,omitempty"`
	Type    string `json:"type,omitempty"`
}

type Media struct {
	*Coding `json:"coding,omitempty"`
}

type PurposeOfUse struct {
	*Coding `json:"coding,omitempty"`
}

type Participant struct {
	Role         []Type         `json:"role,omitempty"`
	Reference    *Reference     `json:"reference,omitempty"`
	UserID       UserID         `json:"userId,omitempty"`
	AltID        string         `json:"altId,omitempty"`
	Name         string         `json:"name,omitempty"`
	Requestor    bool           `json:"requestor,omitempty"`
	Location     *Reference     `json:"location,omitempty"`
	Policy       []string       `json:"policy,omitempty"`
	Media        *Media         `json:"media,omitempty"`
	Network      *Network       `json:"network,omitempty"`
	PurposeOfUse []PurposeOfUse `json:"purposeOfUse,omitempty"`
}

type ExtensionContent struct {
	URL         string `json:"url,omitempty"`
	ValueString string `json:"valueString,omitempty"`
}

type Extension struct {
	URL       string              `json:"url,omitempty"`
	Extension []*ExtensionContent `json:"extension,omitempty"`
}

type Source struct {
	Site       string       `json:"site,omitempty"`
	Identifier Identifier   `json:"identifier,omitempty"`
	Type       []*Coding    `json:"type,omitempty"`
	Extension  []*Extension `json:"extension,omitempty"`
}

type PurposeOfEvent struct {
	Coding `json:"coding,omitempty"`
}

type Event struct {
	Type           *Coding           `json:"type,omitempty"`
	Subtype        []*Coding         `json:"subtype,omitempty"`
	Action         string            `json:"action,omitempty"`
	DateTime       string            `json:"dateTime,omitempty"`
	Outcome        string            `json:"outcome,omitempty"`
	OutcomeDesc    string            `json:"outcomeDesc,omitempty"`
	PurposeOfEvent []*PurposeOfEvent `json:"purposeOfEvent,omitempty"`
}

type RootEvent struct {
	ResourceType    string         `json:"resourceType,omitempty"`
	Event           *Event         `json:"event,omitempty"`
	Participant     []*Participant `json:"participant,omitempty"`
	Source          Source         `json:"source,omitempty"`
	Object          []*Object      `json:"object,omitempty"`
	ServiceIDs      []string       `json:"service_ids,omitempty"`
	SourceIPAddress string         `json:"source_ip_address,omitempty"`
	TargetIPAddress string         `json:"target_ip_address,omitempty"`
}
