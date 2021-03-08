package sonar

import (
	"context"
	"strings"

	"github.com/reviewdog/reviewdog/proto/rdf"
)

// Issue of scan result
type Issue struct {
	Key     string
	Project string

	Rule     string
	Status   string
	Severity Severity

	Hash         string
	Effort       string
	CreationDate string
	UpdateDate   string
	Type         string
	Message      string // This is the main info of an issue
	Line         int
	Component    string
	TextRange    struct {
		StartLine   int
		EndLine     int
		StartOffset int
		EndOffset   int
	}
}

// Severity of sonar issues
type Severity string

// Common ones
const (
	SevInfo     Severity = "INFO"
	SevMinor    Severity = "MINOR"
	SevMajor    Severity = "MAJOR"
	SevCritical Severity = "CRITICAL"
	SevBlocker  Severity = "BLOCKER"
)

// GetIssues get issues
func (c *Client) GetIssues(ctx context.Context, projKey string) ([]*Issue, error) {
	var result struct {
		Issues []*Issue
	}
	_, err := c.Do(ctx, "GET", "api/issues/search", []Query{
		{
			Key:   "componentKeys",
			Value: projKey,
		},
		{
			Key:   "resolved",
			Value: false,
		},
	}, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return result.Issues, nil
}

// GetIssueLink provide external link for issue
func (c *Client) GetIssueLink(issue *Issue) string {
	//"http://localhost:19000/project/issues?id=luna&issues=AXgPbuUbvT_5avwPk_cz&open=AXgPbuUbvT_5avwPk_cz"
	return c.host + "project/issues?id=" + issue.Project + "&issues=" + issue.Key
}

// IssuesToRDF convert to error format
func (c *Client) IssuesToRDF(issues []*Issue) (*rdf.DiagnosticResult, error) {
	result := &rdf.DiagnosticResult{
		Diagnostics: make([]*rdf.Diagnostic, len(issues)),
	}
	if len(issues) == 0 {
		return result, nil
	}
	result.Source = &rdf.Source{
		Name: "sonarqube",
		Url:  c.host + "dashboard?id=" + issues[0].Project,
	}
	for i, issue := range issues {
		d := &rdf.Diagnostic{}
		d.Message = issue.Message
		d.Location = &rdf.Location{
			Path: strings.TrimPrefix(issue.Component, issue.Project+":"),
			Range: &rdf.Range{
				Start: &rdf.Position{
					Line:   int32(issue.TextRange.StartLine),
					Column: int32(issue.TextRange.StartOffset),
				},
				End: &rdf.Position{
					Line:   int32(issue.TextRange.EndLine),
					Column: int32(issue.TextRange.EndOffset),
				},
			},
		}
		d.Code = &rdf.Code{
			Value: issue.Rule,
			Url:   c.GetIssueLink(issue),
		}
		switch issue.Severity {
		case SevCritical, SevBlocker:
			d.Severity = rdf.Severity_ERROR
		case SevMajor, SevMinor:
			d.Severity = rdf.Severity_WARNING
		case SevInfo:
			d.Severity = rdf.Severity_INFO
		}
		result.Diagnostics[i] = d
	}
	return result, nil
}
