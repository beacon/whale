package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	defaultTmplPath := os.Getenv("SONAR_TEMPLATE_PATH")
	if defaultTmplPath == "" {
		defaultTmplPath = "/templates/sonar_report.html"
	}
	var (
		jsonPath          string
		htmlPath          string
		tmplPath          string
		login             string
		qualityGate       string
		enableQualityGate bool
	)
	flag.StringVar(&jsonPath, "json", "", "json output path for sonar result")
	flag.StringVar(&htmlPath, "html", "", "html output path for sonar result")
	flag.StringVar(&tmplPath, "template", defaultTmplPath, "html template path")
	flag.StringVar(&login, "login", "", "Sonar login token")
	flag.StringVar(&qualityGate, "qualityGate", "false", "Enable quality gate to exit with -1 on failure")
	flag.Parse()
	enableQualityGate = qualityGate == "true"
	if htmlPath == "" {
		log.Fatalln("-html is required")
	}
	sonarReport, err := Parse(login)
	if err != nil {
		log.Fatalf("Failed to read sonar report: %s", err.Error())
	}

	rawJSON, err := json.MarshalIndent(sonarReport, "", "\t")
	if err != nil {
		log.Fatalf("Failed to marshal sonar result: %s", err.Error())
	}
	if jsonPath != "" {
		if err := ioutil.WriteFile(jsonPath, rawJSON, os.ModePerm); err != nil {
			log.Fatalf("Failed to write %s:%s", jsonPath, err.Error())
		}
	}

	var buf bytes.Buffer
	if err := renderToFile(tmplPath, htmlPath, sonarReport, &buf); err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Job complete! Files are saved:", jsonPath, htmlPath)
	fmt.Println("Project Status:", sonarReport.Status)
	if enableQualityGate && sonarReport.IsError() {
		fmt.Println("Quality Gate is ERROR, exit with -1")
		os.Exit(-1)
	}
}

func renderToFile(tmplPath, dstHtmlPath string, sonarReport *SonarReport, buf *bytes.Buffer) error {
	if tmplPath == "" {
		return errors.New("require template file path")
	}
	raw, err := ioutil.ReadFile(tmplPath)
	if err != nil {
		return fmt.Errorf("Failed to read template file %s:%v", tmplPath, err)
	}
	tmpl, err := template.New("sonar").Funcs(template.FuncMap{
		"First":  First,
		"Second": Second,
		"IsEven": IsEven,
	}).Parse(string(raw))
	if err != nil {
		return fmt.Errorf("Failed to parse template body from %s:%v", tmplPath, err)
	}

	err = tmpl.Execute(buf, sonarReport)
	if err != nil {
		return fmt.Errorf("Failed to render template into %s:%v", dstHtmlPath, err)
	}
	err = ioutil.WriteFile(dstHtmlPath, buf.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("Failed to create %s:%v", dstHtmlPath, err)
	}
	return nil
}

// Option options
type Option struct {
	Login string `json:"login"`
}

const (
	mCoverage    = "coverage"
	mNewCoverage = "new_coverage"
)

type projectStatus struct {
	ProjectStatus struct {
		Status     string
		Conditions []struct {
			Status         string
			MetricKey      string
			Comparator     string
			PeriodIndex    int
			ErrorThreshold string
			ActualValue    string
		}
	}
}

// Parse parse Sonar
func Parse(login string) (*SonarReport, error) {
	ctx := context.Background()
	sonar, err := New(ctx, login)
	if err != nil {
		return nil, fmt.Errorf("error creating sonar endpoint:%v", err)
	}

	projStat, err := sonar.GetProjectStatus(ctx)
	if err != nil {
		return nil, err
	}

	metricMap, err := sonar.GetComponentMeasures(ctx)
	if err != nil {
		return nil, err
	}
	report, err := getReport(ctx, sonar, metricMap)
	if err != nil {
		return nil, err
	}
	report.URL = sonar.DashboardURL
	report.Status = projStat.ProjectStatus.Status

	return report, nil
}

type measureFunc func(v string) interface{}
type measureMap map[string]string

func (m measureMap) addToTable(category *Category, title string, key string, fn measureFunc) {
	s, ok := m[key]
	if !ok {
		return
	}
	v := fn(s)
	category.Data = append(category.Data, &Data{
		ID:    key,
		Title: title,
		Value: v,
	})
}

func getReport(ctx context.Context, s *Sonar, m measureMap) (r *SonarReport, err error) {
	r = new(SonarReport)

	totalLines, newLines := getInt(m["ncloc"]), getInt(m["new_lines"])
	r.TotalLines, r.NewLines = totalLines.(int), newLines.(int)
	r.Lang, err = s.ParseLangDistribution(ctx, m["ncloc_language_distribution"])
	if err != nil {
		return nil, err
	}

	categories := make([]*Category, 0)

	realiable := &Category{
		ID:    "realiability",
		Title: "可靠性 Reliability",
	}

	m.addToTable(realiable, "缺陷 Bugs", "bugs", getInt)
	m.addToTable(realiable, "新增缺陷 New Bugs", "new_bugs", getInt)
	categories = append(categories, realiable)

	vulnerable := &Category{
		ID:    "security",
		Title: "安全性 Security",
	}
	m.addToTable(vulnerable, "漏洞 Vulnerabilities", "vulnerabilities", getInt)
	m.addToTable(vulnerable, "新增漏洞 New Vulnerabilities", "new_vulnerabilities", getInt)
	m.addToTable(vulnerable, "安全热点 Security Hotspots", "security_hotspots", getInt)
	m.addToTable(vulnerable, "新增安全热点 New Security Hotspots", "new_security_hotspots", getInt)
	categories = append(categories, vulnerable)

	maintain := &Category{
		ID:    "maintainability",
		Title: "可维护性 Maintainability",
	}
	m.addToTable(maintain, "债务 Debts", "sqale_index", parseDebt)
	m.addToTable(maintain, "新增债务 New Debts", "new_technical_debt", parseDebt)
	m.addToTable(maintain, "异味 Code Smell", "code_smells", getInt)
	m.addToTable(maintain, "新增异味 New Code Smell", "new_code_smells", getInt)
	categories = append(categories, maintain)

	cover := &Category{
		ID:    "coverage",
		Title: "覆盖率 Coverage",
	}
	m.addToTable(cover, "覆盖率 Coverage", "coverage", getPercent)
	m.addToTable(cover, "新代码覆盖率 Coverage on New Code", "new_coverage", getPercent)
	m.addToTable(cover, "覆盖的新代码行数 New Lines to Cover", "new_lines_to_cover", getInt)
	categories = append(categories, cover)

	dup := &Category{
		ID:    "duplications",
		Title: "重复 Duplications",
	}
	m.addToTable(dup, "重复代码块 Duplicated Blocks", "duplicated_blocks", getInt)
	m.addToTable(dup, "重复率 Duplications", "duplicated_lines_density", getPercent)
	m.addToTable(dup, "新增代码重复率 Duplications on New Code", "new_duplicated_lines_density", getPercent)
	categories = append(categories, dup)

	if _, ok := m["tests"]; ok {
		tests := &Category{
			ID:    "tests",
			Title: "测试 Tests",
		}
		m.addToTable(tests, "总数 Total", "tests", getInt)
		m.addToTable(tests, "错误 Errors", "test_errors", getInt)
		m.addToTable(tests, "失败 Failures", "test_failures", getInt)
		m.addToTable(tests, "成功率 Success Density", "test_success_density", getPercent)
		m.addToTable(tests, "跳过 Skipped", "skipped_tests", getInt)
		m.addToTable(tests, "测试用时 Execution Time", "test_execution_time", parseMsDuration)
		categories = append(categories, tests)
	}

	for _, c := range categories {
		if len(c.Data) == 0 {
			continue
		}
		r.Categories = append(r.Categories, c)
	}

	return r, nil
}

var httpClient *http.Client

func init() {

	httpClient = &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}
}

func parseDebt(debt string) interface{} {
	debtMinutes, err := strconv.Atoi(debt)
	if err != nil {
		return ""
	}
	var (
		hours int
		days  int
	)

	if debtMinutes != 0 {
		hours = debtMinutes / 60
		days = hours / 8
		hours -= 8 * days
		if days != 0 {
			debt = fmt.Sprint(days, "d")
		} else if hours != 0 {
			debt = fmt.Sprint(hours, "h")
		}
	} else {
		debt = fmt.Sprint(debtMinutes, "min")
	}
	return debt
}

func getPercent(s string) interface{} {
	if s == "" {
		return ""
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		s = ""
		return &s
	}
	return fmt.Sprintf("%.02f", v) + " %"
}

func getInt(s string) interface{} {
	var v int
	var err error
	if s == "" {
		return 0
	}
	v, err = strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

func First(v string) string {
	p := strings.SplitN(v, " ", 2)
	if len(p) < 2 {
		return v
	}
	return p[0]
}

func Second(v string) string {
	p := strings.SplitN(v, " ", 2)
	if len(p) < 2 {
		return ""
	}
	return p[1]
}

func IsEven(v int) bool {
	return v%2 == 0
}

// SonarReport Sonar质量报告
type SonarReport struct {
	URL        string         `json:"url"`
	Status     string         `json:"status"`
	TotalLines int            `json:"total_lines"`
	NewLines   int            `json:"new_lines"`
	Lang       map[string]int `json:"lang"` // 语言->代码数
	Categories []*Category    `json:"categories"`
}

type Category struct {
	ID    string  `json:"id"`
	Title string  `json:"title"`
	Data  []*Data `json:"data,omitempty"`
}

type Data struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Value interface{}
}

// IsError returns if project is error
func (s *SonarReport) IsError() bool {
	return s.Status == "ERROR"
}

// Sonar sonar endpoint
type Sonar struct {
	ProjectKey   string
	ServerURL    string
	DashboardURL string
	CETaskURL    string
	AnalysisID   string

	auth string
}

// ProjectStatus project status
type ProjectStatus struct {
	ProjectStatus struct {
		Status     string
		Conditions []struct {
			Status         string
			MetricKey      string
			Comparator     string
			PeriodIndex    int
			ErrorThreshold string
			ActualValue    string
		}
	}
}

func init() {
	httpClient = &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 15 * time.Second,
	}
}

// New create new sonar endpoint from remains of job and login token
func New(ctx context.Context, login string) (*Sonar, error) {
	info, err := extractReportFile()
	if err != nil {
		return nil, fmt.Errorf("error parsing sonar report file:%v", err)
	}

	projectKey, serverURL, dashboardURL, ceTaskURL := info["projectKey"], info["serverUrl"], info["dashboardUrl"], info["ceTaskUrl"]
	if serverURL == "" || ceTaskURL == "" {
		return nil, errors.New("serverUrl/ceTaskUrl is not found in sonar report file")
	}

	if projectKey == "" {
		log.Fatalf("Project key not found in sonar report file")
	}

	if dashboardURL == "" && projectKey != "" {
		dashboardURL = serverURL + "/dashboard/index/" + projectKey
	}
	sonar := &Sonar{
		ServerURL:    serverURL,
		ProjectKey:   projectKey,
		DashboardURL: dashboardURL,
		CETaskURL:    ceTaskURL,
		auth:         "Basic " + base64.StdEncoding.EncodeToString([]byte(login+":")),
	}

	status, analysisID, err := sonar.GetTaskInfo(ctx)
	if err != nil {
		return nil, err
	}
	if status != "SUCCESS" {
		return nil, fmt.Errorf("Sonar task status is not SUCCESS: %s", status)
	}
	sonar.AnalysisID = analysisID
	return sonar, nil
}

func extractReportFile() (map[string]string, error) {
	m := make(map[string]string)
	for _, sonarDir := range []string{"target/sonar/report-task.txt", ".scannerwork/report-task.txt"} {
		info, err := os.Stat(sonarDir)
		if err != nil || info.IsDir() {
			continue
		}
		file, err := os.Open(sonarDir)
		if err != nil {
			return m, err
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			p := strings.SplitN(scanner.Text(), "=", 2)
			if len(p) == 2 {
				m[p[0]] = p[1]
			}
		}
		err = scanner.Err()
		file.Close()
	}
	return m, nil
}

// Do do something with sonar, call its API
func (s *Sonar) Do(ctx context.Context, method, path string, headers map[string]string, body io.Reader, dst interface{}) (int, error) {
	r, err := http.NewRequest(method, s.ServerURL+path, body)
	if err != nil {
		return 0, err
	}
	r.Header.Set("Authorization", s.auth)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	r = r.WithContext(ctx)
	resp, err := httpClient.Do(r)
	if err != nil {
		return 0, err
	}

	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("%s %s:%s", method, path, resp.Status)
	}

	raw, _ := ioutil.ReadAll(resp.Body)

	if err = json.Unmarshal(raw, dst); err != nil {
		return resp.StatusCode, fmt.Errorf("%s %s error decoding:%v", method, path, err)
	}
	return resp.StatusCode, nil
}

// GetTaskInfo get current analysis task info
func (s *Sonar) GetTaskInfo(ctx context.Context) (status string, analysisID string, err error) {
	var r *http.Request
	r, err = http.NewRequest("GET", s.CETaskURL, nil)
	r.Header.Set("Authorization", s.auth)
	if err != nil {
		return
	}
	ctx, cancelFn := context.WithTimeout(ctx, time.Second*30)
	defer cancelFn()
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			var resp *http.Response
			resp, err = httpClient.Do(r)
			if err != nil {
				return
			}

			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("bad status code when query for task info:%d", resp.StatusCode)
				return
			}
			if resp.Body == nil {
				err = fmt.Errorf("error query for task info: empty body")
				return
			}
			var payload struct {
				Task struct {
					Status     string `json:"status"`
					AnalysisID string `json:"analysisId"`
				} `json:"task"`
			}

			if err = json.NewDecoder(resp.Body).Decode(&payload); err != nil {
				return
			}
			if payload.Task.Status == "IN_PROGRESS" {
				break
			}
			status, analysisID = payload.Task.Status, payload.Task.AnalysisID
			return
		case <-ctx.Done():
			err = ctx.Err()
			return
		}
	}
}

// GetProjectStatus get project status during given analysis
func (s *Sonar) GetProjectStatus(ctx context.Context) (*ProjectStatus, error) {
	projStat := new(ProjectStatus)
	code, err := s.Do(ctx, "GET", "/api/qualitygates/project_status?analysisId="+s.AnalysisID, nil, nil, projStat)
	if code != http.StatusOK || err != nil {
		return nil, fmt.Errorf("error get project status: StatusCode=%d Error=%v", code, err)
	}
	return projStat, nil
}

func (s *Sonar) getLanguages(ctx context.Context) (map[string]string, error) {
	var payload struct {
		Languages []struct {
			Key  string
			Name string
		}
	}
	code, err := s.Do(ctx, "GET", "/api/languages/list", nil, nil, &payload)
	if code != http.StatusOK || err != nil {
		return nil, fmt.Errorf("error listing sonar supported languages: %d - %v", code, err)
	}
	langDict := make(map[string]string)
	for _, l := range payload.Languages {
		langDict[l.Key] = l.Name
	}
	return langDict, nil
}

// GetComponentMeasures get detailed info about project analysis
// curl 'http://172.16.102.1:9000/api/measures/search_history?component=dcs-keel&metrics=sqale_index%2Cduplicated_lines_density%2Cncloc%2Ccoverage%2Cbugs%2Ccode_smells%2Cvulnerabilities&ps=1
// alert_status,quality_gate_details,bugs,new_bugs,reliability_rating,new_reliability_rating,vulnerabilities,new_vulnerabilities,security_rating,new_security_rating,security_hotspots,new_security_hotspots,code_smells,new_code_smells,sqale_rating,new_maintainability_rating,sqale_index,new_technical_debt,coverage,new_coverage,new_lines_to_cover,tests,duplicated_lines_density,new_duplicated_lines_density,duplicated_blocks,ncloc,ncloc_language_distribution,projects,new_lines
func (s *Sonar) GetComponentMeasures(ctx context.Context) (map[string]string, error) {
	metrics := []string{
		"coverage",
		"bugs", "new_bugs",
		"code_smells", "new_code_smells",
		"vulnerabilities", "new_vulnerabilities",
		"duplicated_lines_density", "new_duplicated_lines_density",
		"duplicated_blocks",
		"ncloc_language_distribution", "ncloc",
		"new_technical_debt",
		"sqale_index",
		"new_lines_to_cover", "new_lines",
		"tests", "test_errors", "test_failures", "skipped_tests", "test_success_density", "test_execution_time",
		"security_hotspots", "new_security_hotspots",
	}
	var payload struct {
		Component struct {
			Measures []struct {
				Metric  string
				Value   string
				Periods []struct {
					Index int
					Value string
				}
			}
		}
	}
	code, err := s.Do(ctx, "GET", "/api/measures/component?componentKey="+
		s.ProjectKey+
		"&additionalFields=metrics&metricKeys="+strings.Join(metrics, ","), nil, nil, &payload)
	if code == http.StatusNotFound {
		metrics = metrics[:len(metrics)-2]
		code, err = s.Do(ctx, "GET", "/api/measures/component?componentKey="+
			s.ProjectKey+
			"&additionalFields=metrics&metricKeys="+strings.Join(metrics, ","), nil, nil, &payload)
	}
	if err != nil || code != http.StatusOK {
		return nil, fmt.Errorf("error getting project measures: StatusCode=%d Error=%v", code, err)
	}
	metricMap := make(map[string]string)
	for _, m := range payload.Component.Measures {
		if m.Value != "" {
			metricMap[m.Metric] = m.Value
		} else if len(m.Periods) != 0 {
			metricMap[m.Metric] = m.Periods[0].Value
		}
	}

	return metricMap, nil
}

// ParseLangDistribution parse language distribution
func (s *Sonar) ParseLangDistribution(ctx context.Context, langDist string) (map[string]int, error) {
	m := make(map[string]int)
	if langDist != "" {
		langDict, err := s.getLanguages(ctx)
		if err != nil {
			return m, err
		}
		langs := strings.Split(langDist, ";")
		for _, lang := range langs {
			p := strings.SplitN(lang, "=", 2)
			if len(p) == 2 {
				lineCount, err := strconv.Atoi(p[1])
				if err != nil {
					continue
				}
				langName := langDict[p[0]]
				if langName == "" {
					langName = "Other"
				}
				m[langName] += lineCount
			}
		}
	}
	return m, nil
}

func parseMsDuration(duration string) interface{} {
	if duration == "" {
		return ""
	}
	durationMs, err := strconv.Atoi(duration)
	if err != nil {
		return duration + "ms"
	}
	var (
		seconds int
		hours   int
	)

	if durationMs != 0 {
		seconds = durationMs / 1000
		hours = seconds / 60
		seconds -= 60 * hours
		if hours != 0 {
			return fmt.Sprint(hours, "h")
		} else if seconds != 0 {
			return fmt.Sprint(seconds, "s")
		}
	}
	return fmt.Sprint(durationMs, "ms")
}

// FromMap map->JSON->v
func FromMap(data map[string]interface{}, v interface{}) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("utils.FromMap:failed to marshal map:%v", err)
	}
	return json.Unmarshal(raw, v)
}
