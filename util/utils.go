package util

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Nbccccc/FinderFuzz/config"
)

// HTTPClient HTTP客户端配置
type HTTPClient struct {
	Client  *http.Client
	Headers map[string]string
}

// NewHTTPClient 创建新的HTTP客户端
func NewHTTPClient() *HTTPClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 设置代理
	if config.Conf.Proxy != "" {
		// 如果代理URL没有协议前缀，自动添加http://
		proxyURLStr := config.Conf.Proxy
		if !strings.HasPrefix(proxyURLStr, "http://") && !strings.HasPrefix(proxyURLStr, "https://") && !strings.HasPrefix(proxyURLStr, "socks5://") {
			proxyURLStr = "http://" + proxyURLStr
		}

		proxyURL, err := url.Parse(proxyURLStr)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Conf.Timeout) * time.Millisecond,
	}

	// 创建独立的Headers map，避免多个客户端共享同一个map
	headers := make(map[string]string)
	for key, value := range config.Conf.Headers {
		headers[key] = value
	}

	return &HTTPClient{
		Client:  client,
		Headers: headers,
	}
}

// Get 发送GET请求
func (h *HTTPClient) Get(targetURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	for key, value := range h.Headers {
		req.Header.Set(key, value)
	}

	// 设置默认User-Agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", config.DefaultUserAgent)
	}

	return h.Client.Do(req)
}

// Post 发送POST请求
func (h *HTTPClient) Post(targetURL string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", targetURL, body)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	for key, value := range h.Headers {
		req.Header.Set(key, value)
	}

	// 设置默认Content-Type
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// 设置默认User-Agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", config.DefaultUserAgent)
	}

	return h.Client.Do(req)
}

// Put 发送PUT请求
func (h *HTTPClient) Put(targetURL string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("PUT", targetURL, body)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	for key, value := range h.Headers {
		req.Header.Set(key, value)
	}

	// 设置Content-Type
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	} else if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// 设置默认User-Agent
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", config.DefaultUserAgent)
		}

	return h.Client.Do(req)
}

// Delete 发送DELETE请求
func (h *HTTPClient) Delete(targetURL string) (*http.Response, error) {
	req, err := http.NewRequest("DELETE", targetURL, nil)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	for key, value := range h.Headers {
		req.Header.Set(key, value)
	}

	// 设置默认User-Agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", config.DefaultUserAgent)
	}

	return h.Client.Do(req)
}

// Patch 发送PATCH请求
func (h *HTTPClient) Patch(targetURL string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("PATCH", targetURL, body)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	for key, value := range h.Headers {
		req.Header.Set(key, value)
	}

	// 设置Content-Type
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	} else if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// 设置默认User-Agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", config.DefaultUserAgent)
	}

	return h.Client.Do(req)
}

// Request 发送自定义HTTP请求
func (h *HTTPClient) Request(method, targetURL string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, err
	}

	// 设置自定义头部
	for key, value := range h.Headers {
		req.Header.Set(key, value)
	}

	return h.Client.Do(req)
}

// SetHeader 设置请求头
func (h *HTTPClient) SetHeader(key, value string) {
	if h.Headers == nil {
		h.Headers = make(map[string]string)
	}
	h.Headers[key] = value
}

// SetProxy 设置代理
func (h *HTTPClient) SetProxy(proxyURL string) error {
	if proxyURL == "" {
		return nil
	}

	// 如果代理URL没有协议前缀，自动添加http://
	proxyURLStr := proxyURL
	if !strings.HasPrefix(proxyURLStr, "http://") && !strings.HasPrefix(proxyURLStr, "https://") && !strings.HasPrefix(proxyURLStr, "socks5://") {
		proxyURLStr = "http://" + proxyURLStr
	}

	parsedURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return err
	}

	transport := h.Client.Transport.(*http.Transport)
	transport.Proxy = http.ProxyURL(parsedURL)
	return nil
}

// SetTimeout 设置超时时间
func (h *HTTPClient) SetTimeout(timeout time.Duration) {
	h.Client.Timeout = timeout
}

// RegexFind 正则表达式查找
func RegexFind(pattern, text string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re.FindAllString(text, -1)
}

// RegexFindSubmatch 正则表达式查找子匹配
func RegexFindSubmatch(pattern, text string) [][]string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re.FindAllStringSubmatch(text, -1)
}

// IsValidURL 检查URL是否有效
func IsValidURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// JoinURL 拼接URL
func JoinURL(baseURL, path string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	ref, err := url.Parse(path)
	if err != nil {
		return ""
	}

	return base.ResolveReference(ref).String()
}

// GetDomain 获取域名
func GetDomain(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// GetScheme 获取协议
func GetScheme(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	return u.Scheme
}

// CleanURL 清理URL
func CleanURL(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	// 移除fragment
	u.Fragment = ""

	return u.String()
}

// FilterByRegex 通过正则表达式过滤
func FilterByRegex(items []string, patterns []string) []string {
	var result []string
	for _, item := range items {
		filtered := false
		for _, pattern := range patterns {
			matched, err := regexp.MatchString(pattern, item)
			if err == nil && matched {
				filtered = true
				break
			}
		}
		if !filtered {
			result = append(result, item)
		}
	}
	return result
}

// RemoveDuplicates 去重
func RemoveDuplicates(items []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

// ReadLines 读取文件行
func ReadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

// WriteLines 写入文件行
func WriteLines(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	return writer.Flush()
}

// FormatSize 格式化文件大小
func FormatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// ParseStatusCode 解析状态码过滤器
func ParseStatusCode(statusFilter string) []int {
	if statusFilter == "all" || statusFilter == "" {
		return nil
	}

	var codes []int
	parts := strings.Split(statusFilter, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if code, err := strconv.Atoi(part); err == nil {
			codes = append(codes, code)
		}
	}
	return codes
}

// MatchStatusCode 匹配状态码
func MatchStatusCode(statusCode int, filters []int) bool {
	if len(filters) == 0 {
		return true
	}
	for _, filter := range filters {
		if statusCode == filter {
			return true
		}
	}
	return false
}

// GetFileExtension 获取文件扩展名
func GetFileExtension(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) > 1 {
		return strings.ToLower(parts[len(parts)-1])
	}
	return ""
}

// IsJSFile 判断是否为JS文件
func IsJSFile(filename string) bool {
	ext := GetFileExtension(filename)
	return ext == "js" || ext == "javascript"
}

// NormalizeURL 标准化URL
func NormalizeURL(baseURL, targetURL string) string {
	// 如果是完整URL，直接返回
	if IsValidURL(targetURL) {
		return targetURL
	}

	// 如果以//开头，添加协议
	if strings.HasPrefix(targetURL, "//") {
		scheme := GetScheme(baseURL)
		if scheme == "" {
			scheme = "http"
		}
		return scheme + ":" + targetURL
	}

	// 如果以/开头，拼接域名
	if strings.HasPrefix(targetURL, "/") {
		base, err := url.Parse(baseURL)
		if err != nil {
			return targetURL
		}
		return fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, targetURL)
	}

	// 相对路径，拼接完整URL
	return JoinURL(baseURL, targetURL)
}

// ExtractDomain 提取域名（不包含端口）
func ExtractDomain(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	return host
}

// IsSameDomain 判断是否为同一域名
func IsSameDomain(url1, url2 string) bool {
	domain1 := ExtractDomain(url1)
	domain2 := ExtractDomain(url2)
	return domain1 != "" && domain1 == domain2
}



// TrimQuotes 去除引号
func TrimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// SafeString 安全字符串（用于HTML输出）
func SafeString(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

// Truncate 截断字符串
func Truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length] + "..."
}

// GetResponseSize 获取响应大小
func GetResponseSize(resp *http.Response) int64 {
	if resp == nil {
		return 0
	}
	return resp.ContentLength
}

// IsSuccessStatusCode 判断是否为成功状态码
func IsSuccessStatusCode(code int) bool {
	return code >= 200 && code < 300
}

// IsRedirectStatusCode 判断是否为重定向状态码
func IsRedirectStatusCode(code int) bool {
	return code >= 300 && code < 400
}

// IsClientErrorStatusCode 判断是否为客户端错误状态码
func IsClientErrorStatusCode(code int) bool {
	return code >= 400 && code < 500
}

// IsServerErrorStatusCode 判断是否为服务器错误状态码
func IsServerErrorStatusCode(code int) bool {
	return code >= 500 && code < 600
}

// ReadResponseBody 读取响应体内容
func ReadResponseBody(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// ReadRequestBody 读取请求体内容
func ReadRequestBody(req *http.Request) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// ReadHeadersFromFile 从文件读取请求头
func ReadHeadersFromFile(filename string) (map[string]string, error) {
	headers := make(map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("无法打开headers文件: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析key:value格式
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("headers文件第%d行格式错误，应为 key:value 格式: %s", lineNum, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "" {
			return nil, fmt.Errorf("headers文件第%d行key不能为空: %s", lineNum, line)
		}

		headers[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取headers文件失败: %v", err)
	}

	if len(headers) == 0 {
		return nil, fmt.Errorf("headers文件中没有找到有效的请求头")
	}

	return headers, nil
}

// IsDangerousRoute 检查是否为危险路由
func IsDangerousRoute(targetURL string) bool {
	// 将URL转换为小写进行检查
	lowerURL := strings.ToLower(targetURL)

	for _, keyword := range config.DangerousKeywords {
		if strings.Contains(lowerURL, keyword) {
			return true
		}
	}

	return false
}

// FilterDangerousRoutes 过滤危险路由
func FilterDangerousRoutes(urls []string) []string {
	var filteredURLs []string
	for _, url := range urls {
		if IsDangerousRoute(url) {
			fmt.Printf("[WARN] 跳过危险路由: %s\n", url)
			continue
		}
		filteredURLs = append(filteredURLs, url)
	}
	return filteredURLs
}
