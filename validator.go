package main

import (
	"context"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"

	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// UserMap holds information from the authenticated emails file
type UserMap struct {
	usersFile string
	m         unsafe.Pointer
}

// NewUserMap parses the authenticated emails file into a new UserMap
//
// TODO (@NickMeves): Audit usage of `unsafe.Pointer` and potentially refactor
func NewUserMap(usersFile string, done <-chan bool, onUpdate func()) *UserMap {
	um := &UserMap{usersFile: usersFile}
	m := make(map[string]bool)
	atomic.StorePointer(&um.m, unsafe.Pointer(&m)) // #nosec G103
	if usersFile != "" {
		logger.Printf("using authenticated emails file %s", usersFile)
		WatchForUpdates(usersFile, done, func() {
			um.LoadAuthenticatedEmailsFile()
			onUpdate()
		})
		um.LoadAuthenticatedEmailsFile()
	}
	return um
}

// IsValid checks if an email is allowed
func (um *UserMap) IsValid(email string) (result bool) {
	m := *(*map[string]bool)(atomic.LoadPointer(&um.m))
	_, result = m[email]
	return
}

// LoadAuthenticatedEmailsFile loads the authenticated emails file from disk
// and parses the contents as CSV
func (um *UserMap) LoadAuthenticatedEmailsFile() {
	r, err := os.Open(um.usersFile)
	if err != nil {
		logger.Fatalf("failed opening authenticated-emails-file=%q, %s", um.usersFile, err)
	}
	defer func(c io.Closer) {
		cerr := c.Close()
		if cerr != nil {
			logger.Fatalf("Error closing authenticated emails file: %s", cerr)
		}
	}(r)
	csvReader := csv.NewReader(r)
	csvReader.Comma = ','
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true
	records, err := csvReader.ReadAll()
	if err != nil {
		logger.Errorf("error reading authenticated-emails-file=%q, %s", um.usersFile, err)
		return
	}
	updated := make(map[string]bool)
	for _, r := range records {
		address := strings.ToLower(strings.TrimSpace(r[0]))
		updated[address] = true
	}
	atomic.StorePointer(&um.m, unsafe.Pointer(&updated)) // #nosec G103
}

func newValidatorImpl(domains []string, usersFile string, useKubernetesAnnotations bool, kubeConfig string,
	done <-chan bool, onUpdate func()) func(string, string) bool {
	validUsers := NewUserMap(usersFile, done, onUpdate)

	var k8sClient *kubernetes.Clientset = nil
	if useKubernetesAnnotations {
		k8sClient = configureK8SClient(kubeConfig)
	}

	var allowAll bool
	for i, domain := range domains {
		if domain == "*" {
			allowAll = true
			continue
		}
		domains[i] = strings.ToLower(domain)
	}

	validator := func(email string, host string) (valid bool) {
		if email == "" {
			return
		}
		email = strings.ToLower(email)
		if useKubernetesAnnotations && k8sClient != nil {
			return kubernetesEmailValidation(email, host, k8sClient)
		}
		return defaultEmailValidation(allowAll, email, validUsers, domains)
	}
	return validator
}

// NewValidator constructs a function to validate email addresses
func NewValidator(domains []string, usersFile string, useKubernetesAnnotations bool, kubeConfig string) func(string, string) bool {
	return newValidatorImpl(domains, usersFile, useKubernetesAnnotations, kubeConfig, nil, func() {})
}

func defaultEmailValidation(allowAll bool, email string, validUsers *UserMap, allowedDomains []string) bool {
	if allowAll {
		return true
	}
	valid := isEmailValidWithDomains(email, allowedDomains)
	if !valid {
		valid = validUsers.IsValid(email)
	}
	return valid
}

// isEmailValidWithDomains checks if the authenticated email is validated against the provided domain
func isEmailValidWithDomains(email string, allowedDomains []string) bool {
	for _, domain := range allowedDomains {
		// allow if the domain is perfect suffix match with the email
		if strings.HasSuffix(email, "@"+domain) {
			return true
		}

		// allow if the domain is prefixed with . or *. and
		// the last element (split on @) has the suffix as the domain
		atoms := strings.Split(email, "@")

		if (strings.HasPrefix(domain, ".") && strings.HasSuffix(atoms[len(atoms)-1], domain)) ||
			(strings.HasPrefix(domain, "*.") && strings.HasSuffix(atoms[len(atoms)-1], domain[1:])) {
			return true
		}
	}

	return false
}

func kubernetesEmailValidation(email string, host string, client *kubernetes.Clientset) bool {
	ingress := getKubernetesIngressForHost(host, client)
	// if we can't get ingress information assume that no one is allowed
	if ingress == nil {
		return false
	}
	if val, ok := ingress.Annotations["oauth2-proxy.github.io/users"]; ok {
		for _, user := range strings.Split(val, ",") {
			if strings.TrimSpace(user) == email {
				return true
			}
		}
	}
	return false
}

func getKubernetesIngressForHost(host string, client *kubernetes.Clientset) *v1.Ingress {
	// Ingresses("") means to get ingresses from all namespaces
	ings, err := client.NetworkingV1().Ingresses("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	for _, ingress := range ings.Items {
		for _, rule := range ingress.Spec.Rules {
			if rule.Host == host {
				return &ingress
			}
		}
	}
	return nil
}

func configureK8SClient(kubeConfig string) *kubernetes.Clientset {
	if home := homedir.HomeDir(); home != "" && kubeConfig == "" {
		possibleConfig := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(possibleConfig); err == nil {
			kubeConfig = possibleConfig
		}
	}

	// if kubeConfig == "" this function will use in-cluster kubernetes configuratoin
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	return clientset
}
