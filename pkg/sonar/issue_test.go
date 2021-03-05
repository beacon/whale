package sonar

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

func TestGetIssues(t *testing.T) {
	c, err := NewClient(http.DefaultClient, "http://localhost:19000", "da360061f7144ce19ae7f8059916728f64be0dfa")
	if err != nil {
		t.Fatal(err)
	}
	issues, err := c.GetIssues(context.Background(), "--")
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
}
