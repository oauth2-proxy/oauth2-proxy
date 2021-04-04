package basic

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

func LoadStaticUsers(opts options.StaticUsers) (map[string]options.StaticUser, error) {
	switch {
	case opts.FromHTPasswdFile != "" && opts.FromFile == "" && len(opts.Users) == 0:
		return loadStaticUsersFromHTPasswdFile(opts.FromHTPasswdFile, opts.HTPasswdUserGroups)
	case opts.FromHTPasswdFile == "" && opts.FromFile != "" && len(opts.Users) == 0:
		return loadStaticUsersFromFile(opts.FromFile)
	case opts.FromHTPasswdFile == "" && opts.FromFile == "" && len(opts.Users) > 0:
		return loadStaticUsersInline(opts.Users)
	default:
		return nil, errors.New("exactly one of HTPasswdFile, FromFile and Users must be specified")
	}
}

func loadStaticUsersFromHTPasswdFile(path string, userGroups []string) (map[string]options.StaticUser, error) {
	// We allow HTPasswd location via config options
	r, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("could not open htpasswd file: %v", err)
	}
	defer func(c io.Closer) {
		cerr := c.Close()
		if cerr != nil {
			logger.Fatalf("error closing the htpasswd file: %v", cerr)
		}
	}(r)

	passwdMap, err := newHtpasswd(r)
	if err != nil {
		return nil, fmt.Errorf("could not load read htpasswd file: %v", err)
	}

	users := make(map[string]options.StaticUser)
	for user, pass := range passwdMap.users {
		users[user] = options.StaticUser{
			Username: user,
			Password: pass.(string),
			Groups:   append([]string{}, userGroups...),
		}
	}
	return users, nil
}

func loadStaticUsersFromFile(path string) (map[string]options.StaticUser, error) {
	users := []options.StaticUser{}
	if err := options.LoadYAML(path, &users); err != nil {
		return nil, fmt.Errorf("could not load static user file: %v", err)
	}

	return loadStaticUsersInline(users)
}

func loadStaticUsersInline(inlineUsers []options.StaticUser) (map[string]options.StaticUser, error) {
	users := make(map[string]options.StaticUser)
	for _, user := range inlineUsers {
		if _, ok := users[user.Username]; ok {
			return nil, fmt.Errorf("static user %q provided multiple times", user.Username)
		}
		users[user.Username] = user
	}

	return users, nil
}
