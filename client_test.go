package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/portworx/dcos-secrets/mock"
	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	config := NewDefaultConfig()
	config.Insecure = true

	client, err := NewClient(config)

	assert.Nil(t, err)
	assert.NotNil(t, client)

	// error if certs is missing in secure mode
	config = NewDefaultConfig()

	_, err = NewClient(config)

	assert.NotNil(t, err)
	assert.Equal(t, "CA certificate file missing.", err.Error())

	// error if cannot read certs
	config = NewDefaultConfig()
	config.CACertFile = "/path/to/certificate"

	oldIOUtilReadFile := ioutilReadFile
	defer func() { ioutilReadFile = oldIOUtilReadFile }()
	ioutilReadFile = func(string) ([]byte, error) {
		return nil, fmt.Errorf("failed to read certificate")
	}

	_, err = NewClient(config)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to read certificate")

	// error on invalid certificate
	config = NewDefaultConfig()
	config.CACertFile = "/path/to/certificate"

	ioutilReadFile = func(string) ([]byte, error) {
		return []byte("invalid certificate"), nil
	}

	_, err = NewClient(config)

	assert.NotNil(t, err)
	assert.Equal(t, "Could not parse any CA certificates", err.Error())
}

func TestSecretAPIsWithEmptySecretPath(t *testing.T) {
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTPClient(t),
	}

	_, err := sc.GetSecret("mystore", "")
	assert.NotNil(t, err)
	assert.Equal(t, ErrKeyEmpty, err)

	err = sc.CreateSecret("mystore", "", nil)
	assert.NotNil(t, err)
	assert.Equal(t, ErrKeyEmpty, err)

	err = sc.UpdateSecret("mystore", "", nil)
	assert.NotNil(t, err)
	assert.Equal(t, ErrKeyEmpty, err)

	err = sc.CreateOrUpdateSecret("mystore", "", nil)
	assert.NotNil(t, err)
	assert.Equal(t, ErrKeyEmpty, err)

	err = sc.DeleteSecret("mystore", "")
	assert.NotNil(t, err)
	assert.Equal(t, ErrKeyEmpty, err)
}

func TestSecretAPIsWithInvalidPrefixSlash(t *testing.T) {
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTPClient(t),
	}

	_, err := sc.GetSecret("mystore", "/invalid/path")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "secret should not start with slash")

	err = sc.CreateSecret("mystore", "/invalid/path", nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "secret should not start with slash")

	err = sc.UpdateSecret("mystore", "/invalid/path", nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "secret should not start with slash")

	err = sc.CreateOrUpdateSecret("mystore", "/invalid/path", nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "secret should not start with slash")

	err = sc.DeleteSecret("mystore", "/invalid/path")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "secret should not start with slash")
}

// Test GetSecret

func TestGetSecret(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	expectedSecret := &Secret{
		Value: "testdata",
	}

	expectedBody, _ := json.Marshal(expectedSecret)
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"GET",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				nil,
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer(expectedBody)),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	secret, err := sc.GetSecret("teststore", "path/to/secret")

	assert.Nil(t, err)
	assert.Equal(t, "testdata", secret.Value)
}

func TestGetSecretWithDefaultStore(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	expectedSecret := &Secret{
		Value: "testdata",
	}

	expectedBody, _ := json.Marshal(expectedSecret)
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"GET",
				"https://master.mesos/secrets/v1/secret/default/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				nil,
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer(expectedBody)),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	secret, err := sc.GetSecret("", "path/to/secret")

	assert.Nil(t, err)
	assert.Equal(t, "testdata", secret.Value)
}

func TestGetSecretWithError(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"GET",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				nil,
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusUnauthorized,
			},
			nil,
		).
		Times(1)

	_, err := sc.GetSecret("teststore", "path/to/secret")

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Unauthorized")
}

func TestGetSecretWithInvalidOutput(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	// output json is not of secret type
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"GET",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				nil,
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte(`{"name": "admin"}`))),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	secret, err := sc.GetSecret("teststore", "path/to/secret")

	assert.Nil(t, err)
	assert.Equal(t, "", secret.Value)

	// output json is invalid
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"GET",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				nil,
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte("this should be a json"))),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	_, err = sc.GetSecret("teststore", "path/to/secret")

	assert.NotNil(t, err)
}

// Test CreateSecret

func TestCreateSecret(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	secret := &Secret{
		Value: "testdata",
	}

	expectedReq, _ := json.Marshal(secret)
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PUT",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader(expectedReq)),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	err := sc.CreateSecret("teststore", "path/to/secret", secret)

	assert.Nil(t, err)
}

func TestCreateSecretWithDefaultStore(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	secret := &Secret{
		Value: "testdata",
	}

	expectedReq, _ := json.Marshal(secret)
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PUT",
				"https://master.mesos/secrets/v1/secret/default/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader(expectedReq)),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	err := sc.CreateSecret("", "path/to/secret", secret)

	assert.Nil(t, err)
}

func TestCreateSecretWithError(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	secret := &Secret{
		Value: "testdata",
	}

	expectedReq, _ := json.Marshal(secret)
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PUT",
				"https://master.mesos/secrets/v1/secret/default/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader(expectedReq)),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusForbidden,
			},
			nil,
		).
		Times(1)

	err := sc.CreateSecret("", "path/to/secret", secret)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Forbidden")
}

// Test UpdateSecret

func TestUpdateSecret(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	secret := &Secret{
		Value: "testdata",
	}

	expectedReq, _ := json.Marshal(secret)
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PATCH",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader(expectedReq)),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	err := sc.UpdateSecret("teststore", "path/to/secret", secret)

	assert.Nil(t, err)
}

func TestUpdateSecretWithDefaultStore(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	secret := &Secret{
		Value: "testdata",
	}

	expectedReq, _ := json.Marshal(secret)
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PATCH",
				"https://master.mesos/secrets/v1/secret/default/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader(expectedReq)),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	err := sc.UpdateSecret("", "path/to/secret", secret)

	assert.Nil(t, err)
}

func TestUpdateSecretWithError(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	secret := &Secret{
		Value: "testdata",
	}

	expectedReq, _ := json.Marshal(secret)
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PATCH",
				"https://master.mesos/secrets/v1/secret/default/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader(expectedReq)),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusUnauthorized,
			},
			nil,
		).
		Times(1)

	err := sc.UpdateSecret("", "path/to/secret", secret)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Unauthorized")
}

// Test CreateOrUpdateSecret

func TestCreateOrUpdateSecret(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	secret := &Secret{
		Value: "testdata",
	}
	expectedReq, _ := json.Marshal(secret)

	// create if does not exist
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PUT",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader(expectedReq)),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	err := sc.CreateOrUpdateSecret("teststore", "path/to/secret", secret)

	assert.Nil(t, err)

	// update if secret already exists
	gomock.InOrder(mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PUT",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader(expectedReq)),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusOK,
			},
			fmt.Errorf("secret already exists"),
		).
		Times(1),

		mockHTTP.EXPECT().
			Do(
				RequestMatcher(
					"PATCH",
					"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
					map[string]string{
						"Content-Type": "application/json",
						"Accept":       "application/json",
					},
					ioutil.NopCloser(bytes.NewReader(expectedReq)),
				),
			).
			Return(
				&http.Response{
					Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
					StatusCode: http.StatusOK,
				},
				nil,
			).
			Times(1),
	)

	err = sc.CreateOrUpdateSecret("teststore", "path/to/secret", secret)

	assert.Nil(t, err)
}

func TestCreateOrUpdateSecretWithError(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	secret := &Secret{
		Value: "testdata",
	}
	expectedReq, _ := json.Marshal(secret)

	// create fails
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PUT",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader(expectedReq)),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusForbidden,
			},
			nil,
		).
		Times(1)

	err := sc.CreateOrUpdateSecret("teststore", "path/to/secret", secret)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Forbidden")

	// create fails because secret already exists, but update fails
	gomock.InOrder(mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PUT",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader(expectedReq)),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusOK,
			},
			fmt.Errorf("secret already exists"),
		).
		Times(1),

		mockHTTP.EXPECT().
			Do(
				RequestMatcher(
					"PATCH",
					"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
					map[string]string{
						"Content-Type": "application/json",
						"Accept":       "application/json",
					},
					ioutil.NopCloser(bytes.NewReader(expectedReq)),
				),
			).
			Return(
				&http.Response{
					Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
					StatusCode: http.StatusForbidden,
				},
				nil,
			).
			Times(1),
	)

	err = sc.CreateOrUpdateSecret("teststore", "path/to/secret", secret)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Forbidden")
}

// Test DeleteSecret

func TestDeleteSecret(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"DELETE",
				"https://master.mesos/secrets/v1/secret/teststore/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader([]byte{})),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	err := sc.DeleteSecret("teststore", "path/to/secret")

	assert.Nil(t, err)
}

func TestDeleteSecretWithDefaultStore(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"DELETE",
				"https://master.mesos/secrets/v1/secret/default/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader([]byte{})),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	err := sc.DeleteSecret("", "path/to/secret")

	assert.Nil(t, err)
}

func TestDeleteSecretWithError(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"DELETE",
				"https://master.mesos/secrets/v1/secret/default/path/to/secret",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				ioutil.NopCloser(bytes.NewReader([]byte{})),
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusNotFound,
			},
			nil,
		).
		Times(1)

	err := sc.DeleteSecret("", "path/to/secret")

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "API Error")
}

// Test RevokeSecret

func TestRevokeSecretNotImplemented(t *testing.T) {
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTPClient(t),
	}

	err := sc.RevokeSecret("store", "key")

	assert.NotNil(t, err)
	assert.Equal(t, ErrNotImplemented, err)
}

// Test RenewSecret

func TestRenewSecretNotImplemented(t *testing.T) {
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTPClient(t),
	}

	err := sc.RenewSecret("store", "key", 30)

	assert.NotNil(t, err)
	assert.Equal(t, ErrNotImplemented, err)
}

// Test apiRequest

func TestAPIRequestWithAuthToken(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	authToken := "auth-token"
	sc.UpdateACSToken(authToken)

	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PUT",
				"https://master.mesos/path",
				map[string]string{
					"Content-Type":  "application/json",
					"Accept":        "application/json",
					"Authorization": "token=" + authToken,
				},
				nil,
			),
		).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusOK,
			},
			nil,
		).
		Times(1)

	err := sc.apiRequest("PUT", "/path", "secret", nil)

	assert.Nil(t, err)
}

func TestAPIRequestWithErrorOnHTTPRequest(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	// error on http request
	mockHTTP.EXPECT().
		Do(
			RequestMatcher(
				"PUT",
				"https://master.mesos/path",
				map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				nil,
			),
		).
		Return(
			&http.Response{
				Body: ioutil.NopCloser(bytes.NewBuffer([]byte{})),
			},
			fmt.Errorf("error from HTTP request"),
		).
		Times(1)

	err := sc.apiRequest("PUT", "/path", "secret", nil)

	assert.NotNil(t, err)
	assert.Equal(t, "error from HTTP request", err.Error())
}

func TestAPIRequestWithErrorOnMarshallingInput(t *testing.T) {
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTPClient(t),
	}

	oldJsonMarshal := jsonMarshal
	defer func() { jsonMarshal = oldJsonMarshal }()
	jsonMarshal = func(object interface{}) ([]byte, error) {
		return nil, fmt.Errorf("failed to marshal the input")
	}

	err := sc.apiRequest("PUT", "/path", "secret", nil)

	assert.NotNil(t, err)
	assert.Equal(t, "failed to marshal the input", err.Error())
}

func TestAPIRequestWithErrorOnNewHTTPRequest(t *testing.T) {
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTPClient(t),
	}

	oldHTTPNewRequest := httpNewRequest
	defer func() { httpNewRequest = oldHTTPNewRequest }()
	httpNewRequest = func(string, string, io.Reader) (*http.Request, error) {
		return nil, fmt.Errorf("failed to create HTTP request")
	}

	err := sc.apiRequest("PUT", "/path", "secret", nil)

	assert.NotNil(t, err)
	assert.Equal(t, "failed to create HTTP request", err.Error())
}

func TestAPIRequestWithHTTPError(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	// Unauthorized
	mockHTTP.EXPECT().
		Do(gomock.Any()).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusUnauthorized,
			},
			nil,
		).
		Times(1)

	err := sc.apiRequest("PUT", "/path", "secret", nil)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Unauthorized")

	// Forbidden
	mockHTTP.EXPECT().
		Do(gomock.Any()).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte{})),
				StatusCode: http.StatusForbidden,
			},
			nil,
		).
		Times(1)

	err = sc.apiRequest("PUT", "/path", "secret", nil)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Forbidden")
}

func TestAPIRequestWithNonJsonErrorResponse(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	// non-json error response will return the response as is
	mockHTTP.EXPECT().
		Do(gomock.Any()).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte("error response"))),
				StatusCode: http.StatusInternalServerError,
			},
			nil,
		).
		Times(1)

	oldJsonUnmarshal := jsonUnmarshal
	defer func() { jsonUnmarshal = oldJsonUnmarshal }()
	jsonUnmarshal = func([]byte, interface{}) error {
		return fmt.Errorf("failed to unmarshal the error response")
	}

	err := sc.apiRequest("PUT", "/path", "secret", nil)

	assert.NotNil(t, err)
	assert.Equal(t, "API Error: error response", err.Error())
}

func TestAPIRequestWithJsonErrorResponse(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	// json error response without description will return the response as is
	mockHTTP.EXPECT().
		Do(gomock.Any()).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte(`{"message": "error message"}`))),
				StatusCode: http.StatusInternalServerError,
			},
			nil,
		).
		Times(1)

	err := sc.apiRequest("PUT", "/path", "secret", nil)

	assert.NotNil(t, err)
	assert.Equal(t, "API Error: {\"message\": \"error message\"}", err.Error())

	// json error response with description will return the description as error
	mockHTTP.EXPECT().
		Do(gomock.Any()).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte(`{"description": "error message"}`))),
				StatusCode: http.StatusInternalServerError,
			},
			nil,
		).
		Times(1)

	err = sc.apiRequest("PUT", "/path", "secret", nil)

	assert.NotNil(t, err)
	assert.Equal(t, "API Error: error message", err.Error())
}

func TestAPIRequestWithErrorOnReadingResponseBody(t *testing.T) {
	mockHTTP := mockHTTPClient(t)
	sc := &secretsClient{
		config:     NewDefaultConfig(),
		httpClient: mockHTTP,
	}

	oldIOUtilReadAll := ioutilReadAll
	defer func() { ioutilReadAll = oldIOUtilReadAll }()
	ioutilReadAll = func(r io.Reader) ([]byte, error) {
		return nil, fmt.Errorf("failed to read response body")
	}

	mockHTTP.EXPECT().
		Do(gomock.Any()).
		Return(
			&http.Response{
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte("error message"))),
				StatusCode: http.StatusInternalServerError,
			},
			nil,
		).
		Times(1)

	err := sc.apiRequest("PUT", "/path", "secret", nil)

	assert.NotNil(t, err)
	assert.Equal(t, "failed to read response body", err.Error())
}

// mockHTTPClient returns a mock HTTPClient
func mockHTTPClient(t *testing.T) *mock.MockHTTPClient {
	mockCtrl := gomock.NewController(t)
	mockClient := mock.NewMockHTTPClient(mockCtrl)
	return mockClient
}

// requestMatcher implements gomock Matcher to verify a HTTP request object
type requestMatcher struct {
	method string
	url    string
	header map[string]string
	body   io.ReadCloser
}

func RequestMatcher(method, url string, header map[string]string, body io.ReadCloser) gomock.Matcher {
	return &requestMatcher{
		method: method,
		url:    url,
		header: header,
		body:   body,
	}
}

func (m *requestMatcher) Matches(x interface{}) bool {
	req, ok := x.(*http.Request)
	if !ok {
		return false
	}

	// assert HTTP method/verb
	if req.Method != m.method {
		return false
	}

	// assert url
	u, err := url.Parse(m.url)
	if err != nil {
		return false
	}

	if req.URL.String() != u.String() {
		return false
	}

	// assert headers
	if len(m.header) != len(req.Header) {
		return false
	}
	for k, v := range m.header {
		if req.Header.Get(k) != v {
			return false
		}
	}

	// assert body
	if m.body != nil {
		expectedBody := make([]byte, 200)
		m.body.Read(expectedBody)

		actualBody := make([]byte, 200)
		req.Body.Read(actualBody)

		if string(expectedBody) != string(actualBody) {
			return false
		}
	}

	return true
}

func (m *requestMatcher) String() string {
	return fmt.Sprintf("HTTP Request Matcher: {%s %s %v}", m.method, m.url, m.header)
}
