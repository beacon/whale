/*Package sonar wraps open api*/
package sonar

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Client to access sonar api
type Client struct {
	client  *http.Client
	host    string
	headers map[string]string
	auth    string
}

// NewClient create new client
func NewClient(client *http.Client, host, token string) (*Client, error) {
	if !strings.HasSuffix(host, "/") {
		host += "/"
	}
	return &Client{
		client: client,
		host:   host,
		headers: map[string]string{
			"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(token+":")),
		},
	}, nil
}

// Query pairs
type Query struct {
	Key   string
	Value interface{}
}

// Do do something with sonar, call its API
func (c *Client) Do(ctx context.Context, method, path string, queries []Query, headers map[string]string, body io.Reader, dst interface{}) (int, error) {
	if len(queries) != 0 {
		path += "?"
		for _, q := range queries {
			path += q.Key + "="
			path += url.QueryEscape(fmt.Sprint(q.Value))
			path += "&"
		}
	}
	log.Println("DBG - ", method, c.host+path)
	r, err := http.NewRequest(method, c.host+path, body)
	if err != nil {
		return 0, err
	}
	for k, v := range c.headers {
		r.Header.Set(k, v)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	r = r.WithContext(ctx)
	resp, err := c.client.Do(r)
	if err != nil {
		return 0, err
	}

	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("%s %s:%s", method, path, resp.Status)
	}

	raw, _ := ioutil.ReadAll(resp.Body)
	// TODO: remove debug
	ioutil.WriteFile("response.json", raw, 0644)

	if err = json.Unmarshal(raw, dst); err != nil {
		return resp.StatusCode, fmt.Errorf("%s %s error decoding:%v", method, path, err)
	}
	return resp.StatusCode, nil
}
