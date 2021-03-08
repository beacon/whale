package sonar

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
)

func TestGetIssues(t *testing.T) {
	c, err := NewClient(http.DefaultClient, "http://localhost:19000", "da360061f7144ce19ae7f8059916728f64be0dfa")
	if err != nil {
		t.Fatal(err)
	}
	issues, err := c.GetIssues(context.Background(), "luna")
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create("issues.json")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "\t")
	enc.Encode(&issues)

	diag, err := c.IssuesToRDF(issues)
	if err != nil {
		t.Fatal(err)
	}
	rdjson, err := protojson.Marshal(diag)
	if err != nil {
		t.Fatal(err)
	}
	var rdout bytes.Buffer
	json.Indent(&rdout, rdjson, "", "  ")
	if err := ioutil.WriteFile("diag-rdjson.json", rdout.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}
