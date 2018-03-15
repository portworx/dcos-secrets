package api

import (
	"errors"
	"fmt"
	"strings"
)

type Secret struct {
	Author      string   `json:"author,omitempty"`
	Created     string   `json:"created,omitempty"`
	Description string   `json:"description,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	Value       string   `json:"value,omitempty"`
}

var (
	ErrKeyEmpty = errors.New("Secret path cannot be empty")
)

const (
	defaultSecretStore = "default"
	secretsPath        = "/secrets/v1/secret"
)

func (s *secretsClient) GetSecret(store, key string) (*Secret, error) {
	path, err := s.getSecretsPath(store, key)
	if err != nil {
		return nil, err
	}

	secret := new(Secret)
	if err := s.apiGet(path, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func (s *secretsClient) CreateSecret(store, key string, secret *Secret) error {
	path, err := s.getSecretsPath(store, key)
	if err != nil {
		return err
	}
	return s.apiPut(path, secret, nil)
}

func (s *secretsClient) UpdateSecret(store, key string, secret *Secret) error {
	path, err := s.getSecretsPath(store, key)
	if err != nil {
		return err
	}
	return s.apiPatch(path, secret, nil)
}

func (s *secretsClient) DeleteSecret(store, key string) error {
	path, err := s.getSecretsPath(store, key)
	if err != nil {
		return err
	}
	return s.apiDelete(path, nil)
}

func (s *secretsClient) getSecretsPath(store, key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", ErrKeyEmpty
	} else if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("Path to secret should not start with slash")
	}

	if strings.TrimSpace(store) == "" {
		store = defaultSecretStore
	}

	apiPath := fmt.Sprintf("%s/%s/%s", secretsPath, store, key)
	return apiPath, nil
}
