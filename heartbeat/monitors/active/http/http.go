// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package http

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/beats/v7/heartbeat/monitors/plugin"
	"github.com/elastic/beats/v7/heartbeat/monitors/wrappers/wraputil"
	"github.com/elastic/beats/v7/libbeat/version"
	conf "github.com/elastic/elastic-agent-libs/config"

	"github.com/elastic/beats/v7/heartbeat/monitors/jobs"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent-libs/useragent"
)

func init() {
	plugin.Register("http", create, "synthetics/http")
}

var userAgent = useragent.UserAgent("Heartbeat", version.GetDefaultVersion(), version.Commit(), version.BuildTime().String())

// replaceTemplateVars replaces {{var}} or {{var|format}} in the input string with dynamic values.
func replaceTemplateVars(input string) string {
	templateRe := regexp.MustCompile(`\{\{\s*\$?([a-zA-Z0-9_]+)(?:\|([^}]+))?\s*}}`)
	return templateRe.ReplaceAllStringFunc(input, func(match string) string {
		groups := templateRe.FindStringSubmatch(match)
		if len(groups) < 2 {
			return match
		}
		key := groups[1]
		format := ""
		if len(groups) > 2 {
			format = groups[2]
		}
		switch key {
		case "date":
			if format == "" {
				format = "2006-01-02" // 기본 포맷
			}
			// Go의 날짜 포맷 문자열로 변환
			goFormat := convertToGoDateFormat(format)
			return time.Now().Format(goFormat)
		case "guid", "randomUUID":
			return generateUUID()
		case "timestamp":
			return fmt.Sprintf("%d", time.Now().Unix())
		case "randomInt":
			if format != "" {
				// format에 범위가 지정된 경우 (예: "1-100")
				if strings.Contains(format, "-") {
					parts := strings.Split(format, "-")
					if len(parts) == 2 {
						min, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
						max, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
						if max > min {
							randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
							return fmt.Sprintf("%d", randInt.Int64()+int64(min))
						}
					}
				}
			}
			// 기본값: 0-1000
			randInt, _ := rand.Int(rand.Reader, big.NewInt(1001))
			return fmt.Sprintf("%d", randInt.Int64())
		case "randomBoolean":
			randInt, _ := rand.Int(rand.Reader, big.NewInt(2))
			if randInt.Int64() == 0 {
				return "false"
			}
			return "true"
		case "randomHex":
			length := 16 // 기본 길이
			if format != "" {
				if parsedLength, err := strconv.Atoi(format); err == nil && parsedLength > 0 {
					length = parsedLength
				}
			}
			bytes := make([]byte, length/2)
			rand.Read(bytes)
			return fmt.Sprintf("%x", bytes)
		case "randomAlphaNumeric":
			length := 10 // 기본 길이
			if format != "" {
				if parsedLength, err := strconv.Atoi(format); err == nil && parsedLength > 0 {
					length = parsedLength
				}
			}
			const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			result := make([]byte, length)
			for i := range result {
				randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
				result[i] = charset[randInt.Int64()]
			}
			return string(result)
		case "randomAlpha":
			length := 10 // 기본 길이
			if format != "" {
				if parsedLength, err := strconv.Atoi(format); err == nil && parsedLength > 0 {
					length = parsedLength
				}
			}
			const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
			result := make([]byte, length)
			for i := range result {
				randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
				result[i] = charset[randInt.Int64()]
			}
			return string(result)
		case "randomWords":
			words := []string{"lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit", "sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore", "magna", "aliqua"}
			count := 3 // 기본 단어 수
			if format != "" {
				if parsedCount, err := strconv.Atoi(format); err == nil && parsedCount > 0 {
					count = parsedCount
				}
			}
			if count > len(words) {
				count = len(words)
			}
			result := make([]string, count)
			for i := 0; i < count; i++ {
				randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
				result[i] = words[randInt.Int64()]
			}
			return strings.Join(result, " ")
		case "randomPhoneNumber":
			formats := []string{"###-###-####", "(###) ###-####", "###.###.####"}
			formatIndex := 0
			if format != "" {
				if parsedIndex, err := strconv.Atoi(format); err == nil && parsedIndex >= 0 && parsedIndex < len(formats) {
					formatIndex = parsedIndex
				}
			}
			phoneFormat := formats[formatIndex]
			result := phoneFormat
			for i := 0; i < 10; i++ {
				randInt, _ := rand.Int(rand.Reader, big.NewInt(10))
				digit := fmt.Sprintf("%d", randInt.Int64())
				result = strings.Replace(result, "#", digit, 1)
			}
			return result
		case "randomEmail":
			domains := []string{"example.com", "test.com", "sample.org", "demo.net"}
			domainIndex := 0
			if format != "" {
				if parsedIndex, err := strconv.Atoi(format); err == nil && parsedIndex >= 0 && parsedIndex < len(domains) {
					domainIndex = parsedIndex
				}
			}
			username := generateRandomAlpha(8)
			return fmt.Sprintf("%s@%s", username, domains[domainIndex])
		case "randomFirstName":
			names := []string{"John", "Jane", "Michael", "Sarah", "David", "Emily", "Robert", "Lisa", "James", "Jennifer", "William", "Jessica", "Richard", "Amanda", "Thomas", "Melissa", "Christopher", "Nicole", "Daniel", "Stephanie"}
			randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(names))))
			return names[randInt.Int64()]
		case "randomLastName":
			names := []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"}
			randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(names))))
			return names[randInt.Int64()]
		case "randomFullName":
			firstName := replaceTemplateVars("{{$randomFirstName}}")
			lastName := replaceTemplateVars("{{$randomLastName}}")
			return fmt.Sprintf("%s %s", firstName, lastName)
		case "randomUserName":
			length := 8 // 기본 길이
			if format != "" {
				if parsedLength, err := strconv.Atoi(format); err == nil && parsedLength > 0 {
					length = parsedLength
				}
			}
			const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
			result := make([]byte, length)
			for i := range result {
				randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
				result[i] = charset[randInt.Int64()]
			}
			return string(result)
		case "randomPassword":
			length := 12 // 기본 길이
			if format != "" {
				if parsedLength, err := strconv.Atoi(format); err == nil && parsedLength > 0 {
					length = parsedLength
				}
			}
			const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
			result := make([]byte, length)
			for i := range result {
				randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
				result[i] = charset[randInt.Int64()]
			}
			return string(result)
		default:
			return match // 알 수 없는 변수는 그대로 둠
		}
	})
}

// generateRandomAlpha generates a random alphabetic string of given length
func generateRandomAlpha(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, length)
	for i := range result {
		randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[randInt.Int64()]
	}
	return string(result)
}

// generateUUID generates a random UUID v4 string
func generateUUID() string {
	uuid := make([]byte, 16)
	rand.Read(uuid)
	
	// Set version (4) and variant bits
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// convertToGoDateFormat converts common date format patterns to Go's date format
func convertToGoDateFormat(format string) string {
	// 일반적인 날짜 포맷을 Go의 날짜 포맷으로 변환
	format = strings.ReplaceAll(format, "YYYY", "2006")
	format = strings.ReplaceAll(format, "MM", "01")
	format = strings.ReplaceAll(format, "DD", "02")
	format = strings.ReplaceAll(format, "HH", "15")
	format = strings.ReplaceAll(format, "mm", "04")
	format = strings.ReplaceAll(format, "ss", "05")
	return format
}
// Create makes a new HTTP monitor
func create(
	name string,
	cfg *conf.C,
) (p plugin.Plugin, err error) {
	config := defaultConfig()
	if err := cfg.Unpack(&config); err != nil {
		return plugin.Plugin{}, err
	}

	var body []byte
	var enc contentEncoder

	if config.Check.Request.SendBody != "" {
		// 템플릿 변수 치환
		replacedBody := replaceTemplateVars(config.Check.Request.SendBody)
		var err error
		compression := config.Check.Request.Compression
		enc, err = getContentEncoder(compression.Type, compression.Level)
		if err != nil {
			return plugin.Plugin{}, err
		}

		buf := bytes.NewBuffer(nil)
		err = enc.Encode(buf, bytes.NewBufferString(replacedBody))
		if err != nil {
			return plugin.Plugin{}, err
		}

		body = buf.Bytes()
	}

	validator, err := makeValidateResponse(&config.Check.Response)
	if err != nil {
		return plugin.Plugin{}, err
	}

	// Determine whether we're using a proxy or not and then use that to figure out how to
	// run the job
	var makeJob func(string) (jobs.Job, error)
	// In the event that a ProxyURL is present, or redirect support is enabled
	// we execute DNS resolution requests inline with the request, not running them as a separate job, and not returning
	// separate DNS rtt data.
	if (config.Transport.Proxy.URL != nil && !config.Transport.Proxy.Disable) || config.MaxRedirects > 0 {
		transport, err := newRoundTripper(&config)
		if err != nil {
			return plugin.Plugin{}, err
		}

		makeJob = func(urlStr string) (jobs.Job, error) {
			return newHTTPMonitorHostJob(urlStr, &config, transport, enc, body, validator)
		}
	} else {
		// preload TLS configuration
		tls, err := tlscommon.LoadTLSConfig(config.Transport.TLS)
		if err != nil {
			return plugin.Plugin{}, err
		}
		config.Transport.TLS = nil

		makeJob = func(urlStr string) (jobs.Job, error) {
			return newHTTPMonitorIPsJob(&config, urlStr, tls, enc, body, validator)
		}
	}

	js := make([]jobs.Job, len(config.Hosts))
	for i, urlStr := range config.Hosts {
		u, err := url.Parse(urlStr)
		if err != nil {
			return plugin.Plugin{}, err
		}

		job, err := makeJob(urlStr)
		if err != nil {
			return plugin.Plugin{}, err
		}

		// Assign any execution errors to the error field and
		// assign the url field
		js[i] = wraputil.WithURLField(u, job)
	}

	return plugin.Plugin{Jobs: js, Endpoints: len(config.Hosts)}, nil
}

func newRoundTripper(config *Config) (http.RoundTripper, error) {
	return config.Transport.RoundTripper(
		httpcommon.WithAPMHTTPInstrumentation(),
		httpcommon.WithoutProxyEnvironmentVariables(),
		httpcommon.WithKeepaliveSettings{
			Disable: true,
		},
		httpcommon.WithHeaderRoundTripper(map[string]string{"User-Agent": userAgent}),
	)
}
