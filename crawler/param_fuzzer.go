package crawler

import (
	"bufio"
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Nbccccc/FinderFuzz/config"
	"github.com/Nbccccc/FinderFuzz/mode"
	"github.com/Nbccccc/FinderFuzz/util"
)

// ParamFuzzer 参数模糊测试器
type ParamFuzzer struct {
	HTTPClient *util.HTTPClient
	Crawler    *Crawler
	BaseURL    string
	Results    []mode.ParamFuzzResult
}



// NewParamFuzzer 创建新的参数模糊测试器
func NewParamFuzzer(baseURL string, crawler *Crawler) *ParamFuzzer {
	return &ParamFuzzer{
		HTTPClient: util.NewHTTPClient(),
		Crawler:    crawler,
		BaseURL:    baseURL,
		Results:    []mode.ParamFuzzResult{},
	}
}

// GetResults 获取参数模糊测试结果
func (pf *ParamFuzzer) GetResults() []mode.ParamFuzzResult {
	return pf.Results
}

// StartParamFuzzing 开始参数模糊测试
func (pf *ParamFuzzer) StartParamFuzzing() error {
	fmt.Printf("[INFO] 开始参数模糊测试\n")

	// 分析已爬取的页面，寻找参数错误提示
	candidateURLs := pf.findCandidateURLs()
	fmt.Printf("[INFO] 发现可能需要参数的URL: %d个\n", len(candidateURLs))

	if len(candidateURLs) == 0 {
		fmt.Printf("[WARN] 未发现包含参数错误提示的页面，跳过参数模糊测试\n")
		return nil
	}

	// 询问用户是否进行参数模糊测试
	if !pf.askUserConfirmation(candidateURLs) {
		fmt.Printf("[INFO] 用户选择跳过参数模糊测试\n")
		return nil
	}

	// 对每个候选URL进行参数模糊测试
	for _, candidateURL := range candidateURLs {
		fmt.Printf("[INFO] 对URL进行参数模糊测试: %s\n", candidateURL.URL)
		result := pf.fuzzURLParams(candidateURL)
		if result != nil {
			pf.Results = append(pf.Results, *result)
		}
	}

	fmt.Printf("[INFO] 参数模糊测试完成，发现结果: %d个\n", len(pf.Results))
	return nil
}

// CandidateURL 候选URL结构
type CandidateURL struct {
	URL        string
	Method     string
	StatusCode int
	Content    string
	ErrorHints []string
}

// findCandidateURLs 查找包含参数错误提示的候选URL
func (pf *ParamFuzzer) findCandidateURLs() []CandidateURL {
	var candidates []CandidateURL

	// 遍历已爬取的链接
	for _, link := range pf.Crawler.Links {
		// 跳过危险路由
			if util.IsDangerousRoute(link.Url) {
				fmt.Printf("[WARN] 跳过危险路由参数模糊测试: %s\n", link.Url)
				continue
			}
		// 跳过成功的请求（200状态码通常不会有参数错误提示）
		if link.Status == "200" {
			continue
		}

		// 检查不同的HTTP方法
		methods := []string{"GET"}

		// 如果是405状态码，说明方法不允许，需要尝试其他方法
		if link.Status == "405" {
			methods = config.HTTPMethods
		}

		for _, method := range methods {
			// 发送请求获取完整内容
			var resp *http.Response
			var err error

			switch method {
			case "GET":
				resp, err = pf.HTTPClient.Get(link.Url)
			case "POST":
				req, reqErr := http.NewRequest("POST", link.Url, strings.NewReader("{}"))
				if reqErr != nil {
					err = reqErr
					break
				}
				req.Header.Set("Content-Type", "application/json")
				for key, value := range pf.HTTPClient.Headers {
					req.Header.Set(key, value)
				}
				resp, err = pf.HTTPClient.Client.Do(req)
			case "PUT":
				resp, err = pf.HTTPClient.Put(link.Url, "application/json", strings.NewReader("{}"))
			case "DELETE":
				resp, err = pf.HTTPClient.Delete(link.Url)
			case "PATCH":
				resp, err = pf.HTTPClient.Patch(link.Url, "application/json", strings.NewReader("{}"))
			default:
				continue
			}

			if err != nil {
				continue
			}
			defer resp.Body.Close()

			body, err := util.ReadResponseBody(resp)
			if err != nil {
				continue
			}

			content := string(body)
			errorHints := pf.extractParamErrorHints(content)

			// 检查是否找到参数错误提示，或者状态码表明需要参数
			if len(errorHints) > 0 || pf.isParamRequiredStatus(resp.StatusCode) {
				// 如果没有错误提示但状态码表明需要参数，添加通用提示
				if len(errorHints) == 0 {
					errorHints = pf.generateStatusBasedHints(resp.StatusCode, method)
				}

				candidates = append(candidates, CandidateURL{
					URL:        link.Url,
					Method:     method,
					StatusCode: resp.StatusCode,
					Content:    content,
					ErrorHints: errorHints,
				})

				// 找到有效方法后跳出循环
				break
			}
		}
	}

	return candidates
}

// extractParamErrorHints 从页面内容中提取参数错误提示
func (pf *ParamFuzzer) extractParamErrorHints(content string) []string {
	var hints []string
	contentLower := strings.ToLower(content)

	// 检查参数错误关键词
	for _, keyword := range config.ParamErrorKeywords {
		keywordLower := strings.ToLower(keyword)
		if strings.Contains(contentLower, keywordLower) {
			// 提取包含关键词的句子或段落
			hint := pf.extractErrorContext(content, keyword)
			if hint != "" && !pf.containsHint(hints, hint) {
				hints = append(hints, hint)
			}
		}
	}

	// 使用正则表达式查找可能的参数名提示
	paramHints := pf.extractParamNamesFromError(content)
	hints = append(hints, paramHints...)

	return hints
}

// extractErrorContext 提取错误上下文
func (pf *ParamFuzzer) extractErrorContext(content, keyword string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(keyword)) {
			// 清理HTML标签
			cleanLine := pf.cleanHTML(line)
			cleanLine = strings.TrimSpace(cleanLine)
			if len(cleanLine) > 10 && len(cleanLine) < 200 {
				return cleanLine
			}
		}
	}
	return ""
}

// extractParamNamesFromError 从错误信息中提取可能的参数名
func (pf *ParamFuzzer) extractParamNamesFromError(content string) []string {
	var paramNames []string

	// 常见的参数名提取模式
	for _, pattern := range config.ParamNamePatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				paramName := strings.TrimSpace(match[1])
				if len(paramName) > 1 && len(paramName) < 50 {
					paramNames = append(paramNames, paramName)
				}
			}
		}
	}

	return util.RemoveDuplicates(paramNames)
}

// cleanHTML 清理HTML标签
func (pf *ParamFuzzer) cleanHTML(text string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	text = re.ReplaceAllString(text, "")
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

// containsHint 检查提示是否已存在
func (pf *ParamFuzzer) containsHint(hints []string, hint string) bool {
	for _, h := range hints {
		if strings.EqualFold(h, hint) {
			return true
		}
	}
	return false
}

// isParamRequiredStatus 检查状态码是否表明需要参数
func (pf *ParamFuzzer) isParamRequiredStatus(statusCode int) bool {
	// 400: Bad Request - 通常表示缺少必需参数
	// 422: Unprocessable Entity - 请求格式正确但语义错误，可能缺少参数
	// 404: Not Found - 在某些API中表示缺少路径参数
	return statusCode == 400 || statusCode == 422 || statusCode == 404
}

// generateStatusBasedHints 根据状态码生成提示信息
func (pf *ParamFuzzer) generateStatusBasedHints(statusCode int, method string) []string {
	var hints []string

	switch statusCode {
	case 400:
		hints = append(hints, fmt.Sprintf("Bad Request - %s方法可能缺少必需参数", method))
	case 422:
		hints = append(hints, fmt.Sprintf("Unprocessable Entity - %s请求可能缺少参数或参数格式错误", method))
	case 404:
		hints = append(hints, fmt.Sprintf("Not Found - %s请求可能缺少路径参数或查询参数", method))
	default:
		hints = append(hints, fmt.Sprintf("状态码%d表明%s请求可能需要参数", statusCode, method))
	}

	return hints
}

// askUserConfirmation 询问用户确认
func (pf *ParamFuzzer) askUserConfirmation(candidates []CandidateURL) bool {
	fmt.Printf("\n[PARAM-FUZZ] 发现以下URL可能需要参数:\n")
	for i, candidate := range candidates {
		fmt.Printf("  %d. %s (状态码: %d)\n", i+1, candidate.URL, candidate.StatusCode)
		for _, hint := range candidate.ErrorHints {
			fmt.Printf("     提示: %s\n", hint)
		}
	}

	fmt.Printf("\n是否进行参数模糊测试? (y/N): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))

	return input == "y" || input == "yes"
}

// fuzzURLParams 对URL进行参数模糊测试
func (pf *ParamFuzzer) fuzzURLParams(candidate CandidateURL) *mode.ParamFuzzResult {
	result := &mode.ParamFuzzResult{
		URL:              candidate.URL,
		Method:           candidate.Method,
		OriginalStatus:   candidate.StatusCode,
		ErrorHints:       candidate.ErrorHints,
		FuzzedParams:     []string{},
		SuccessfulParams: []string{},
		ParamSource:      "error_message",
		TestResults:      []mode.ParamTestResult{},
	}

	// 从错误提示中提取的参数名
	extractedParams := pf.extractParamNamesFromError(candidate.Content)
	result.FuzzedParams = append(result.FuzzedParams, extractedParams...)

	// 添加常见参数名
	result.FuzzedParams = append(result.FuzzedParams, config.CommonParams...)

	// 去重
	result.FuzzedParams = util.RemoveDuplicates(result.FuzzedParams)

	fmt.Printf("[INFO] 准备测试 %d 个参数\n", len(result.FuzzedParams))

	// 创建工作池进行并发测试
	workChan := make(chan string, len(result.FuzzedParams))
	resultChan := make(chan mode.ParamTestResult, len(result.FuzzedParams))
	var wg sync.WaitGroup

	// 启动工作协程
	for i := 0; i < config.Conf.Thread; i++ {
		wg.Add(1)
		go pf.paramTestWorker(candidate, workChan, resultChan, &wg)
	}

	// 添加测试任务
	for _, param := range result.FuzzedParams {
		workChan <- param
	}
	close(workChan)

	// 等待所有任务完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果
	for testResult := range resultChan {
		result.TestResults = append(result.TestResults, testResult)
		if testResult.Success {
			result.SuccessfulParams = append(result.SuccessfulParams, testResult.ParamName)
			fmt.Printf("[SUCCESS] 发现有效参数: %s (状态码: %d)\n", testResult.ParamName, testResult.StatusCode)
		}
	}

	return result
}

// paramTestWorker 参数测试工作协程
func (pf *ParamFuzzer) paramTestWorker(candidate CandidateURL, workChan <-chan string, resultChan chan<- mode.ParamTestResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for paramName := range workChan {
		testResult := pf.testSingleParam(candidate, paramName)
		resultChan <- testResult
		time.Sleep(time.Duration(config.Conf.Timeout) * time.Millisecond / 10) // 减少请求频率
	}
}

// testSingleParam 测试单个参数
func (pf *ParamFuzzer) testSingleParam(candidate CandidateURL, paramName string) mode.ParamTestResult {
	testResult := mode.ParamTestResult{
		ParamName:  paramName,
		ParamValue: "test", // 使用简单的测试值
		Method:     candidate.Method,
		HasChange:  false,
		Success:    false,
	}

	// 根据HTTP方法发送不同的请求
	var resp *http.Response
	var err error
	var req *http.Request
	var requestBody string // 保存请求体内容

	switch candidate.Method {
	case "GET":
		// 构造测试URL
		testURL := pf.buildTestURL(candidate.URL, paramName, testResult.ParamValue)
		req, err = http.NewRequest("GET", testURL, nil)
		if err == nil {
			pf.setCommonHeaders(req)
			resp, err = pf.HTTPClient.Client.Do(req)
		}
	case "POST":
		// 尝试多种Content-Type格式，包括文件上传
		for _, contentType := range config.ContentTypes {
			if contentType == "multipart/form-data" {
				// 构建文件上传请求
				body, boundary, err := pf.buildFileUploadData(paramName, testResult.ParamValue)
				if err != nil {
					continue
				}
				req, err = http.NewRequest("POST", candidate.URL, bytes.NewReader(body))
				if err == nil {
					req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
					pf.setFileUploadHeaders(req)
					requestBody = string(body)
					resp, err = pf.HTTPClient.Client.Do(req)
					if err == nil {
						// 检查这种格式是否有效（排除415错误）
						if resp.StatusCode != 415 && pf.checkResponse(resp, candidate) {
							break // 找到有效格式，停止尝试
						}
						resp.Body.Close()
					}
				}
			} else {
				// 普通POST请求
				requestBody = pf.buildTestDataWithContentType(paramName, testResult.ParamValue, contentType)
				req, err = http.NewRequest("POST", candidate.URL, strings.NewReader(requestBody))
				if err == nil {
					req.Header.Set("Content-Type", contentType)
					pf.setCommonHeaders(req)
					resp, err = pf.HTTPClient.Client.Do(req)
					if err == nil {
						// 检查这种格式是否有效（排除415错误）
						if resp.StatusCode != 415 && pf.checkResponse(resp, candidate) {
							break // 找到有效格式，停止尝试
						}
						resp.Body.Close()
					}
				}
			}
		}
	case "PUT":
		// 尝试多种Content-Type格式
		for _, contentType := range config.BasicContentTypes {
			requestBody = pf.buildTestDataWithContentType(paramName, testResult.ParamValue, contentType)
			req, err = http.NewRequest("PUT", candidate.URL, strings.NewReader(requestBody))
			if err == nil {
				req.Header.Set("Content-Type", contentType)
				pf.setCommonHeaders(req)
				resp, err = pf.HTTPClient.Client.Do(req)
				if err == nil {
					// 检查这种格式是否有效（排除415错误）
					if resp.StatusCode != 415 && pf.checkResponse(resp, candidate) {
						break // 找到有效格式，停止尝试
					}
					resp.Body.Close()
				}
			}
		}
	case "DELETE":
		// DELETE请求可以在URL中添加参数
		testURL := pf.buildTestURL(candidate.URL, paramName, testResult.ParamValue)
		req, err = http.NewRequest("DELETE", testURL, nil)
		if err == nil {
			pf.setCommonHeaders(req)
			resp, err = pf.HTTPClient.Client.Do(req)
		}
	case "PATCH":
		// 尝试多种Content-Type格式
		for _, contentType := range config.BasicContentTypes {
			requestBody = pf.buildTestDataWithContentType(paramName, testResult.ParamValue, contentType)
			req, err = http.NewRequest("PATCH", candidate.URL, strings.NewReader(requestBody))
			if err == nil {
				req.Header.Set("Content-Type", contentType)
				pf.setCommonHeaders(req)
				resp, err = pf.HTTPClient.Client.Do(req)
				if err == nil {
					// 检查这种格式是否有效（排除415错误）
					if resp.StatusCode != 415 && pf.checkResponse(resp, candidate) {
						break // 找到有效格式，停止尝试
					}
					resp.Body.Close()
				}
			}
		}
	default:
		testResult.ErrorMsg = fmt.Sprintf("不支持的HTTP方法: %s", candidate.Method)
		return testResult
	}

	// 记录请求数据包
	if req != nil {
		testResult.RequestData = pf.formatRequestDataWithBody(req, requestBody)
	}

	if err != nil {
		testResult.ErrorMsg = err.Error()
		return testResult
	}
	defer resp.Body.Close()

	body, err := util.ReadResponseBody(resp)
	if err != nil {
		testResult.ErrorMsg = err.Error()
		return testResult
	}

	// 记录响应数据包
	testResult.ResponseData = pf.formatResponseData(resp, string(body))

	testResult.StatusCode = resp.StatusCode
	testResult.ResponseSize = len(body)

	// 检查响应是否有变化
	if resp.StatusCode != candidate.StatusCode {
		testResult.HasChange = true
		testResult.Success = true
	} else {
		// 检查响应内容是否有变化
		if pf.hasContentChange(candidate.Content, string(body)) {
			testResult.HasChange = true
			testResult.Success = true
		}
	}

	return testResult
}

// buildTestURL 构造测试URL
func (pf *ParamFuzzer) buildTestURL(baseURL, paramName, paramValue string) string {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	query := parsedURL.Query()
	query.Set(paramName, paramValue)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String()
}

// buildTestData 构造测试数据（JSON格式）
func (pf *ParamFuzzer) buildTestData(paramName, paramValue string) string {
	return fmt.Sprintf(`{"%s":"%s"}`, paramName, paramValue)
}

// buildTestDataWithContentType 根据Content-Type构造测试数据
func (pf *ParamFuzzer) buildTestDataWithContentType(paramName, paramValue, contentType string) string {
	switch contentType {
	case "application/json":
		return fmt.Sprintf(`{"%s":"%s"}`, paramName, paramValue)
	case "application/x-www-form-urlencoded":
		return fmt.Sprintf("%s=%s", url.QueryEscape(paramName), url.QueryEscape(paramValue))
	case "text/plain":
		return fmt.Sprintf("%s=%s", paramName, paramValue)
	default:
		return fmt.Sprintf(`{"%s":"%s"}`, paramName, paramValue)
	}
}

// setCommonHeaders 设置通用请求头
func (pf *ParamFuzzer) setCommonHeaders(req *http.Request) {
	// 设置User-Agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", config.ParamFuzzUserAgent)
	}

	// 设置Host头
	if req.Header.Get("Host") == "" && req.URL.Host != "" {
		req.Header.Set("Host", req.URL.Host)
	}

	// 应用用户自定义头部
	for key, value := range pf.HTTPClient.Headers {
		// 不覆盖已经设置的Content-Type头
		if strings.ToLower(key) == "content-type" && req.Header.Get("Content-Type") != "" {
			continue
		}
		req.Header.Set(key, value)
	}
}

// checkResponse 检查响应是否表明参数有效
func (pf *ParamFuzzer) checkResponse(resp *http.Response, candidate CandidateURL) bool {
	// 如果状态码发生变化，说明参数可能有效
	if resp.StatusCode != candidate.StatusCode {
		return true
	}

	// 读取响应内容进行进一步检查
	body, err := util.ReadResponseBody(resp)
	if err != nil {
		return false
	}

	// 检查响应内容是否有变化
	return pf.hasContentChange(candidate.Content, string(body))
}

// hasContentChange 检查内容是否有变化
func (pf *ParamFuzzer) hasContentChange(originalContent, newContent string) bool {
	// 简单的内容变化检测
	if len(newContent) != len(originalContent) {
		return true
	}

	// 检查是否不再包含参数错误关键词
	originalLower := strings.ToLower(originalContent)
	newLower := strings.ToLower(newContent)

	for _, keyword := range config.ParamErrorKeywords {
		keywordLower := strings.ToLower(keyword)
		originalHas := strings.Contains(originalLower, keywordLower)
		newHas := strings.Contains(newLower, keywordLower)

		// 如果原来有错误提示，现在没有了，说明参数有效
		if originalHas && !newHas {
			return true
		}
	}

	return false
}

// formatRequestData 格式化HTTP请求数据包
func (pf *ParamFuzzer) formatRequestData(req *http.Request) string {
	var requestData strings.Builder

	// 请求行
	requestData.WriteString(fmt.Sprintf("%s %s %s\r\n", req.Method, req.URL.RequestURI(), req.Proto))

	// 请求头
	for name, values := range req.Header {
		for _, value := range values {
			requestData.WriteString(fmt.Sprintf("%s: %s\r\n", name, value))
		}
	}

	// 空行分隔头部和主体
	requestData.WriteString("\r\n")

	// 请求主体
	if req.Body != nil {
		body, err := util.ReadRequestBody(req)
		if err == nil {
			requestData.WriteString(string(body))
		}
	}

	return requestData.String()
}

// formatRequestDataWithBody 格式化HTTP请求数据包（带请求体）
func (pf *ParamFuzzer) formatRequestDataWithBody(req *http.Request, requestBody string) string {
	var requestData strings.Builder

	// 请求行
	requestData.WriteString(fmt.Sprintf("%s %s %s\r\n", req.Method, req.URL.RequestURI(), req.Proto))

	// 复制请求头并添加Content-Length
	headers := make(map[string][]string)
	for name, values := range req.Header {
		headers[name] = values
	}

	// 如果有请求体，确保设置Content-Length
	if requestBody != "" {
		headers["Content-Length"] = []string{fmt.Sprintf("%d", len(requestBody))}
	}

	// 输出请求头
	for name, values := range headers {
		for _, value := range values {
			requestData.WriteString(fmt.Sprintf("%s: %s\r\n", name, value))
		}
	}

	// 空行分隔头部和主体
	requestData.WriteString("\r\n")

	// 请求主体
	if requestBody != "" {
		requestData.WriteString(requestBody)
	}

	return requestData.String()
}

// formatResponseData 格式化HTTP响应数据包
func (pf *ParamFuzzer) formatResponseData(resp *http.Response, body string) string {
	var responseData strings.Builder

	// 状态行
	responseData.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))

	// 响应头
	for name, values := range resp.Header {
		for _, value := range values {
			responseData.WriteString(fmt.Sprintf("%s: %s\r\n", name, value))
		}
	}

	// 空行分隔头部和主体
	responseData.WriteString("\r\n")

	// 响应主体（限制长度避免过大）
	if len(body) > 2000 {
		responseData.WriteString(body[:2000])
		responseData.WriteString("\n\n[响应主体过长，已截断...]")
	} else {
		responseData.WriteString(body)
	}

	return responseData.String()
}

// buildFileUploadData 构建文件上传的multipart/form-data数据
func (pf *ParamFuzzer) buildFileUploadData(paramName, paramValue string) ([]byte, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// 添加文件字段
	part, err := writer.CreateFormFile(paramName, config.FileUploadTestData["filename"])
	if err != nil {
		return nil, "", err
	}
	_, err = part.Write([]byte(config.FileUploadTestData["content"]))
	if err != nil {
		return nil, "", err
	}

	// 添加其他表单字段（如果有参数值）
	if paramValue != "" && paramValue != "test" {
		err = writer.WriteField(paramName+"_value", paramValue)
		if err != nil {
			return nil, "", err
		}
	}

	err = writer.Close()
	if err != nil {
		return nil, "", err
	}

	return buf.Bytes(), writer.Boundary(), nil
}

// setFileUploadHeaders 设置文件上传专用请求头
func (pf *ParamFuzzer) setFileUploadHeaders(req *http.Request) {
	// 设置文件上传专用的请求头
	for key, value := range config.FileUploadHeaders {
		req.Header.Set(key, value)
	}

	// 设置Host头
	if req.Header.Get("Host") == "" && req.URL.Host != "" {
		req.Header.Set("Host", req.URL.Host)
	}

	// 应用用户自定义头部（但不覆盖已设置的重要头部）
	for key, value := range pf.HTTPClient.Headers {
		// 不覆盖已经设置的Content-Type头和文件上传专用头
		if strings.ToLower(key) == "content-type" && req.Header.Get("Content-Type") != "" {
			continue
		}
		if strings.ToLower(key) == "user-agent" && req.Header.Get("User-Agent") != "" {
			continue
		}
		if strings.ToLower(key) == "accept" && req.Header.Get("Accept") != "" {
			continue
		}
		req.Header.Set(key, value)
	}
}
