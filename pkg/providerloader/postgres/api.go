package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

type API struct {
	configStore ConfigStore
	conf        options.API
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (errRes ErrorResponse) Error() string {
	return fmt.Sprintf("code=%d: %s", errRes.Code, errRes.Message)
}

func NewAPI(conf options.API, rs *RedisStore, proxyPrefix string) error {
	r := mux.NewRouter()
	api := API{
		configStore: rs,
		conf:        conf,
	}
	var pathPrefix = proxyPrefix

	if conf.PathPrefix != "" {
		pathPrefix = conf.PathPrefix
	}

	if conf.ReadHeaderTimeout == 0 {
		conf.ReadHeaderTimeout = 10 * time.Second
	}

	r2 := r.PathPrefix(pathPrefix).Subrouter()
	r2.HandleFunc("/provider", api.CreateHandler).Methods("POST")
	r2.HandleFunc("/provider", api.UpdateHandler).Methods("PUT")
	r2.HandleFunc("/provider/{id}", api.GetHandler).Methods("GET")
	r2.HandleFunc("/provider/{id}", api.DeleteHandler).Methods("DELETE")

	timeoutErr := ErrorResponse{
		Code:    http.StatusServiceUnavailable,
		Message: "request timed out",
	}
	errMsgJSON, _ := json.Marshal(timeoutErr)
	server := &http.Server{
		Handler:           http.TimeoutHandler(r, conf.HandlerTimeout, string(errMsgJSON)),
		Addr:              conf.Host + ":" + strconv.Itoa(conf.Port),
		ReadHeaderTimeout: conf.ReadHeaderTimeout,
	}

	go func() {
		err := server.ListenAndServe()
		if err != nil && errors.Is(err, http.ErrServerClosed) {
			log.Fatal("server is closed invalid config")
		}
	}()

	return nil
}

// CreateHandler defines the handler for api call through which
// new provider configuration is added in the database.
// It returns status created in when successful.
func (api *API) CreateHandler(rw http.ResponseWriter, req *http.Request) {
	// Before a config entry is added in the db it is validated to
	// avoid failures and crashes.
	code, err := api.addOrUpdateProviderConfig(req, api.configStore.Create) // configStore.Create is used as action here,
	if err != nil {
		writeErrorResponse(rw, code, err.Error())
		return
	}

	// Status Created (201) is returned in case of success.
	rw.WriteHeader(http.StatusCreated)
}

// This function handles the get requests and return provider config in response.
func (api *API) GetHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	providerConf, err := api.configStore.Get(req.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErrorResponse(rw, http.StatusNotFound, err.Error())
			return
		}
		writeErrorResponse(rw, http.StatusInternalServerError, err.Error())
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "application/json")
	fmt.Fprint(rw, providerConf)
}

// This function handles delete requests and remove the specific provider's config
// from db/store.
func (api *API) DeleteHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	err := api.configStore.Delete(req.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErrorResponse(rw, http.StatusNotFound, err.Error())
			return
		}
		writeErrorResponse(rw, http.StatusInternalServerError, err.Error())
		return
	}

	rw.WriteHeader(http.StatusNoContent)
}

// This handler updates the provider config in the config store and cache
// store as well.
func (api *API) UpdateHandler(rw http.ResponseWriter, req *http.Request) {

	code, err := api.addOrUpdateProviderConfig(req, api.configStore.Update)
	if err != nil {
		writeErrorResponse(rw, code, err.Error())
		return
	}

	rw.WriteHeader(http.StatusAccepted) // in case of success status accepted is written in response
}

// ValidateProviderConfig validates the provider configuration and returns provider ID and error
func (api *API) validateProviderConfig(providerconfigJSON []byte) (string, error) {

	var providerConf *options.Provider

	err := json.Unmarshal(providerconfigJSON, &providerConf)
	if err != nil {
		return "", fmt.Errorf("error while decoding JSON. %w", err)
	}

	if providerConf.ID == "" {
		return "", fmt.Errorf("provider ID is not provided")
	}
	_, err = providers.NewProvider(*providerConf)
	if err != nil {
		return "", fmt.Errorf("invalid provider configuration: %w", err)
	}

	return providerConf.ID, nil
}

func writeErrorResponse(rw http.ResponseWriter, code int, message string) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	newErr := ErrorResponse{
		Code:    code,
		Message: message,
	}

	j, _ := json.Marshal(newErr)
	fmt.Fprint(rw, string(j))
}

type createOrUpdateAction func(ctx context.Context, providerID string, providerConfig []byte) error

// This function takes request as input along with action createOrUpdate.
// This action is responsible for configStore related logic,
// It returns status Code for response and error.
// In case of no error, statusCode 0 is returned.
func (api *API) addOrUpdateProviderConfig(req *http.Request, action createOrUpdateAction) (int, error) {
	providerConf, err := io.ReadAll(req.Body)
	defer req.Body.Close()

	if err != nil {
		return http.StatusBadRequest, err
	}
	id, err := api.validateProviderConfig(providerConf)
	if err != nil {
		return http.StatusBadRequest, err
	}

	err = action(req.Context(), id, providerConf)
	if err != nil {
		return getHTTPCodeFromError(err), err
	}

	return 0, nil
}

func getHTTPCodeFromError(err error) int {
	switch {
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrAlreadyExists):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
