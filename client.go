package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

type DCOSSecrets interface {
	GetSecret(store, key string) (*Secret, error)
	CreateSecret(store, key string, secret *Secret) error
	UpdateSecret(store, key string, secret *Secret) error
	CreateOrUpdateSecret(store, key string, secret *Secret) error
	DeleteSecret(store, key string) error
}

type secretsClient struct {
	config     Config
	httpClient *http.Client
}

func NewClient(config Config) (DCOSSecrets, error) {
	tlsConfig, err := getTLSConfig(config)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &secretsClient{
		config:     config,
		httpClient: httpClient,
	}, nil
}

func getTLSConfig(config Config) (*tls.Config, error) {
	if config.Insecure {
		return &tls.Config{
			InsecureSkipVerify: true,
		}, nil
	}

	if config.CACertFile == "" {
		return nil, fmt.Errorf("CA certificate file missing.")
	}

	caCert, err := ioutil.ReadFile(config.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read CA certs. %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		RootCAs: caCertPool,
	}, nil
}

func (s *secretsClient) apiGet(path string, result interface{}) error {
	return s.apiRequest("GET", path, nil, result)
}

func (s *secretsClient) apiPut(path string, body, result interface{}) error {
	return s.apiRequest("PUT", path, body, result)
}

func (s *secretsClient) apiPatch(path string, body, result interface{}) error {
	return s.apiRequest("PATCH", path, body, result)
}

func (s *secretsClient) apiDelete(path string, result interface{}) error {
	return s.apiRequest("DELETE", path, nil, result)
}

func (s *secretsClient) apiRequest(method, path string, body, result interface{}) error {
	var requestBody []byte
	var err error

	if body != nil {
		if requestBody, err = json.Marshal(body); err != nil {
			return err
		}
	}

	request, err := s.buildJSONRequest(method, path, bytes.NewReader(requestBody))
	if err != nil {
		return err
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		if result != nil {
			if err := json.Unmarshal(responseBody, result); err != nil {
				return err
			}
		}
		return nil
	}

	return NewAPIError(responseBody)
}

type JWTToken struct {
	Token string `json:"token"`
}

func (s *secretsClient) buildJSONRequest(method string, path string, reader io.Reader) (*http.Request, error) {
	url := s.config.URL + path
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}

	if s.config.ACSToken != "" {
		request.Header.Add("Authorization", "token="+s.config.ACSToken)
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Accept", "application/json")

	return request, nil
}
