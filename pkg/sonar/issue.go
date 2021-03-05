package sonar

import "context"

// Issue of scan result
type Issue struct {
	Key      string
	Rule     string
	Status   string
	Severity string

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

// GetIssues get issues
func (c *Client) GetIssues(ctx context.Context, projKey string) ([]*Issue, error) {
	var result struct {
		Issues []*Issue
	}
	_, err := c.Do(ctx, "GET", "/api/issues/search", []Query{
		{
			Key:   "componentKeys",
			Value: projKey,
		},
	}, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return result.Issues, nil
}
