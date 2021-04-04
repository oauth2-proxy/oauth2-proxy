package options

// StaticUsers allows admins to define a list of static or local user accounts.
// These users may authenticate to the proxy using basic authentication.
type StaticUsers struct {
	// FromHTPasswdFile allows users to load a set of usernames and passwords from
	// and HTPasswd file.
	FromHTPasswdFile string `json:"fromHTPasswdFile,omitempty"`

	// HTPasswdUserGroups adds additional groups to any user session which has
	// been created from a user defined in the HTPasswdFile.
	HTPasswdUserGroups []string `json:"htpasswdUserGroups,omitempty"`

	// FromFile allows static user definitions to be defined in a separate file.
	// This should be used as an alternative to defining them inline in `users`.
	FromFile string `json:"fromFile,omitempty"`

	// Users defines a list of static or local users and the required information
	// for the proxy to build a session from them.
	// If you prefer not to define users inline, you may define them in a separate
	// file and pass the path to this as `fromFile`.
	Users []StaticUser `json:"users,omitempty"`
}

// StaticUser represents a user and the information required to build a session
// once the user becomes authenticated.
type StaticUser struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}
