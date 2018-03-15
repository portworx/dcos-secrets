package dsecrets

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
)

type DCOSSecrets interface {
	GetSecret(path string) (*Secret, error)
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
		return nil, fmt.Errorf("CA certificate file missing")
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
