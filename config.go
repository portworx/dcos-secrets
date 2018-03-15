package api

type Config struct {
	URL        string
	CACertFile string
	Insecure   bool
	ACSToken   string
}

func NewDefaultConfig() Config {
	return Config{
		URL:      "https://master.mesos",
		Insecure: false,
	}
}
