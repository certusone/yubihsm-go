package connector

import (
	"bytes"
	"fmt"
	"github.com/certusone/aiakos/commands"
	"io/ioutil"
	"net/http"
	"strings"
)

type (
	HTTPConnector struct {
		URL string
	}

	Status         string
	StatusResponse struct {
		Status  Status
		Serial  string
		Version string
		Pid     string
		Address string
		Port    string
	}
)

func NewHTTPConnector(url string) *HTTPConnector {
	return &HTTPConnector{
		URL: url,
	}
}

func (c *HTTPConnector) Request(command *commands.CommandMessage) ([]byte, error) {
	requestData, err := command.Serialize()
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Post("http://"+c.URL+"/connector/api", "application/octet-stream", bytes.NewReader(requestData))
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non OK status code %d", res.StatusCode)
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (c *HTTPConnector) GetStatus() (*StatusResponse, error) {
	res, err := http.DefaultClient.Get("http://" + c.URL + "/connector/status")
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	bodyString := string(data)
	pairs := strings.Split(bodyString, "\n")

	var values []string
	for _, pair := range pairs {
		values = append(values, strings.Split(pair, "=")...)
	}

	status := &StatusResponse{}
	status.Status = Status(values[1])
	status.Serial = values[3]
	status.Version = values[5]
	status.Pid = values[7]
	status.Address = values[9]
	status.Port = values[11]

	return status, nil
}
