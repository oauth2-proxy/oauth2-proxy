package postgres

import (
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

func (api *API) CreateHandler(rw http.ResponseWriter, req *http.Request) {
	var providerConf []byte
	var err error
	providerConf, err = io.ReadAll(req.Body)
	defer req.Body.Close()

	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, err.Error())
		return
	}
	id, err := api.validateProviderConfig(providerConf)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, err.Error())
		return
	}

	err = api.configStore.Create(req.Context(), id, providerConf)
	if err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			writeErrorResponse(rw, http.StatusConflict, err.Error())
			return
		}
		writeErrorResponse(rw, http.StatusInternalServerError, err.Error())
		return
	}

	rw.WriteHeader(http.StatusCreated)
}

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

func (api *API) UpdateHandler(rw http.ResponseWriter, req *http.Request) {
	var providerConf []byte
	var err error
	providerConf, err = io.ReadAll(req.Body)
	defer req.Body.Close()

	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, err.Error())
		return
	}
	id, err := api.validateProviderConfig(providerConf)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, err.Error())
		return

	}

	err = api.configStore.Update(req.Context(), id, providerConf)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErrorResponse(rw, http.StatusNotFound, err.Error())
			return
		}
		writeErrorResponse(rw, http.StatusInternalServerError, err.Error())
		return
	}

	rw.WriteHeader(http.StatusAccepted)

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
