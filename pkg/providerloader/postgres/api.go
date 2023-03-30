package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

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

	r2 := r.PathPrefix(pathPrefix).Subrouter()
	r2.HandleFunc("/provider", api.CreateHandler).Methods("POST")
	r2.HandleFunc("/provider", api.UpdateHandler).Methods("PUT")
	r2.HandleFunc("/provider/{id}", api.GetHandler).Methods("GET")
	r2.HandleFunc("/provider/{id}", api.DeleteHandler).Methods("DELETE")

	server := &http.Server{
		Handler:           r,
		Addr:              conf.Host + ":" + strconv.Itoa(conf.Port),
		ReadHeaderTimeout: conf.Timeout,
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
	id, providerConf, err := api.validateProviderConfig(req)
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
	id, data, err := api.validateProviderConfig(req)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, err.Error())
		return

	}

	err = api.configStore.Update(req.Context(), id, data)
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

func (api *API) validateProviderConfig(req *http.Request) (string, []byte, error) {
	var body []byte
	var err error
	body, err = io.ReadAll(req.Body)
	defer req.Body.Close()

	if err != nil {
		return "", nil, fmt.Errorf("error while reading request body. %v", err)
	}

	var providerConf *options.Provider

	err = json.Unmarshal(body, &providerConf)
	if err != nil {
		return "", nil, fmt.Errorf("error while decoding JSON. %v", err)
	}

	if providerConf.ID == "" {
		return "", nil, fmt.Errorf("provider ID is not provided")
	}

	_, err = providers.NewProvider(*providerConf)
	if err != nil {
		return "", nil, fmt.Errorf("invalid provider configuration: %v", err)
	}

	data, err := json.Marshal(providerConf)
	if err != nil {
		return "", nil, fmt.Errorf("error in marshalling")
	}

	return providerConf.ID, data, nil
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
