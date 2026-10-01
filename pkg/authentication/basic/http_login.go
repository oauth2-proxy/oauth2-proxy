package basic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AppLoginValidator
type AppLoginValidator struct {
	LoginURL string
	Timeout  time.Duration
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Validate implement Validator interface
func (v *AppLoginValidator) Validate(user, password string) bool {
	reqBody := loginRequest{
		Username: user,
		Password: password,
	}
	data, _ := json.Marshal(reqBody)

	client := &http.Client{Timeout: v.Timeout}
	resp, err := client.Post(v.LoginURL, "application/json", bytes.NewReader(data))
	if err != nil {
		println(err.Error())
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("ReadAll error: %v\n", err)
			return false
		}

		fmt.Printf("Response body: %s\n", string(body))
		return false
	}

	return true
}
