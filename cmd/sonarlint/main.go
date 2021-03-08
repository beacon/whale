package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/beacon/whale/pkg/sonar"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	var host string
	var token string
	var project string
	flag.StringVar(&host, "host", "", "Host of sonarqube")
	flag.StringVar(&token, "token", "", "Token of sonarqube")
	flag.StringVar(&project, "project", "", "Project key of sonarqube project")
	flag.Parse()
	if host == "" || project == "" || token == "" {
		log.Fatalln("These parameters are required: --host, --token, --project")
	}
	client, err := sonar.NewClient(http.DefaultClient, host, token)
	if err != nil {
		log.Fatalln("failed to init sonar client:", err)
	}
	issues, err := client.GetIssues(context.Background(), project)
	if err != nil {
		log.Fatalln("failed to get issues of project:", err)
	}
	diag, err := client.IssuesToRDF(issues)
	if err != nil {
		log.Fatalln("failed to get diagnostics from issues:", err)
	}
	var out bytes.Buffer
	rdfjson, err := protojson.Marshal(diag)
	if err != nil {
		log.Fatalln("failed to marshal diagnostics:", err)
	}
	if err := json.Indent(&out, rdfjson, "", "  "); err != nil {
		log.Fatalln("failed to indent json:", err)
	}
	fmt.Println(out.String())
}
