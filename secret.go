package dsecrets

type Secret struct {
	Author      string   `json:"author,omitempty"`
	Created     string   `json:"created,omitempty"`
	Description string   `json:"description,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	Value       string   `json:"value,omitempty"`
}

func (s *secretsClient) GetSecret(path string) (*Secret, error) {
	return &Secret{}, nil
}
