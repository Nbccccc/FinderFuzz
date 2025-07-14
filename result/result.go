package result

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nbccccc/FinderFuzz/mode"
	"github.com/Nbccccc/FinderFuzz/util"
)

// Reporter 报告生成器
type Reporter struct {
	JSFiles                    []mode.JSFile
	Links                      []mode.Link
	SensitiveInfo              []mode.Info
	FuzzResults                []mode.FuzzResult
	DomainInfo                 []mode.DomainInfo
	AuthorityResults           []mode.AuthorityResult
	UnauthorityResults         []mode.UnauthorityResult
	PrivilegeEscalationResults []mode.PrivilegeEscalationResult
	ParamFuzzResults           []mode.ParamFuzzResult
	StatusFilter               []int
	OutputFile                 string
	Format                     string
}

// NewReporter 创建新的报告生成器
func NewReporter(jsFiles []mode.JSFile, links []mode.Link, sensitiveInfo []mode.Info, fuzzResults []mode.FuzzResult, domainInfo []mode.DomainInfo, authorityResults []mode.AuthorityResult, unauthorityResults []mode.UnauthorityResult, privilegeEscalationResults []mode.PrivilegeEscalationResult, paramFuzzResults []mode.ParamFuzzResult) *Reporter {
	return &Reporter{
		JSFiles:                    jsFiles,
		Links:                      links,
		SensitiveInfo:              sensitiveInfo,
		FuzzResults:                fuzzResults,
		DomainInfo:                 domainInfo,
		AuthorityResults:           authorityResults,
		UnauthorityResults:         unauthorityResults,
		PrivilegeEscalationResults: privilegeEscalationResults,
		ParamFuzzResults:           paramFuzzResults,
		StatusFilter:               []int{},
	}
}

// SetStatusFilter 设置状态码过滤器
func (r *Reporter) SetStatusFilter(statusCodes []int) {
	r.StatusFilter = statusCodes
}

// SetOutput 设置输出文件和格式
func (r *Reporter) SetOutput(outputFile, format string) {
	r.OutputFile = outputFile
	r.Format = format
}

// Generate 生成报告
func (r *Reporter) Generate() error {
	switch strings.ToLower(r.Format) {
	case "csv":
		return r.generateCSV()
	case "json":
		return r.generateJSON()
	case "html":
		return r.generateHTML()
	default:
		return fmt.Errorf("不支持的输出格式: %s", r.Format)
	}
}

// generateCSV 生成CSV报告
func (r *Reporter) generateCSV() error {
	file, err := os.Create(r.OutputFile)
	if err != nil {
		return fmt.Errorf("创建CSV文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	header := []string{"类型", "URL", "方法", "状态码", "大小", "标题", "来源", "载荷", "模糊类型", "错误"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("写入CSV表头失败: %v", err)
	}

	// 写入模糊测试结果
	filteredResults := r.filterFuzzResults()
	for _, result := range filteredResults {
		record := []string{
			"Fuzz",
			result.URL,
			result.Method,
			strconv.Itoa(result.Status),
			util.FormatSize(int64(result.Size)),
			result.Title,
			result.Source,
			result.Payload,
			result.FuzzType,
			result.Error,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV记录失败: %v", err)
		}
	}

	// 写入JS文件
	for _, jsFile := range r.JSFiles {
		record := []string{
			"JSFile",
			jsFile.Url,
			"GET",
			jsFile.Status,
			jsFile.Size,
			"",
			jsFile.Source,
			"",
			"",
			"",
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV记录失败: %v", err)
		}
	}

	// 写入链接
	for _, link := range r.Links {
		record := []string{
			"Link",
			link.Url,
			"GET",
			link.Status,
			link.Size,
			link.Title,
			"",
			"",
			"",
			"",
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV记录失败: %v", err)
		}
	}

	// 写入敏感信息
	for _, info := range r.SensitiveInfo {
		record := []string{
			"Sensitive",
			info.Source,
			"",
			"",
			"",
			"敏感信息",
			info.Source,
			"",
			"",
			"",
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV记录失败: %v", err)
		}
	}

	// 写入权限检测结果
	for _, result := range r.AuthorityResults {
		vulnStatus := "否"
		if result.Vulnerable {
			vulnStatus = "是"
		}
		statusCode := result.AuthStatusCode
		if statusCode == 0 {
			statusCode = result.NoAuthStatusCode
		}
		record := []string{
			"Authority",
			result.URL,
			"GET",
			strconv.Itoa(statusCode),
			"",
			"权限检测",
			"",
			vulnStatus,
			result.Reason,
			"",
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV记录失败: %v", err)
		}
	}

	// 写入未授权访问检测结果
	for _, result := range r.UnauthorityResults {
		vulnStatus := "否"
		if result.Vulnerable {
			vulnStatus = "是"
		}
		statusCode := result.AuthStatusCode
		if statusCode == 0 {
			statusCode = result.NoAuthStatusCode
		}
		record := []string{
			"Unauthority",
			result.URL,
			"GET",
			strconv.Itoa(statusCode),
			"",
			"未授权访问检测",
			"",
			vulnStatus,
			result.Reason,
			"",
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV记录失败: %v", err)
		}
	}

	// 写入未授权访问检测结果
	for _, result := range r.PrivilegeEscalationResults {
		vulnStatus := "否"
		if result.Vulnerable {
			vulnStatus = "是"
		}
		statusCode := result.LowAuthStatusCode
		if statusCode == 0 {
			statusCode = result.HighAuthStatusCode
		}
		record := []string{
			"PrivilegeEscalation",
			result.URL,
			"GET",
			strconv.Itoa(statusCode),
			"",
			"未授权访问检测",
			"",
			vulnStatus,
			result.Reason,
			"",
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV记录失败: %v", err)
		}
	}

	fmt.Printf("[INFO] CSV报告已生成: %s\n", r.OutputFile)
	return nil
}

// generateJSON 生成JSON报告
func (r *Reporter) generateJSON() error {
	report := map[string]interface{}{
		"timestamp":                    time.Now().Format("2006-01-02 15:04:05"),
		"js_files":                     r.JSFiles,
		"links":                        r.Links,
		"sensitive_info":               r.SensitiveInfo,
		"fuzz_results":                 r.filterFuzzResults(),
		"authority_results":            r.AuthorityResults,
		"unauthority_results":          r.UnauthorityResults,
		"privilege_escalation_results": r.PrivilegeEscalationResults,
		"param_fuzz_results":           r.ParamFuzzResults,
		"summary": map[string]int{
			"js_files_count":                     len(r.JSFiles),
			"links_count":                        len(r.Links),
			"sensitive_info_count":               len(r.SensitiveInfo),
			"fuzz_results_count":                 len(r.filterFuzzResults()),
			"authority_results_count":            len(r.AuthorityResults),
			"unauthority_results_count":          len(r.UnauthorityResults),
			"privilege_escalation_results_count": len(r.PrivilegeEscalationResults),
			"param_fuzz_results_count":           len(r.ParamFuzzResults),
		},
	}

	file, err := os.Create(r.OutputFile)
	if err != nil {
		return fmt.Errorf("创建JSON文件失败: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("写入JSON文件失败: %v", err)
	}

	fmt.Printf("[INFO] JSON报告已生成: %s\n", r.OutputFile)
	return nil
}

// generateHTML 生成HTML报告
func (r *Reporter) generateHTML() error {
	templateData := r.prepareHTMLData()

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"formatSize":                  r.formatSizeHelper,
		"formatTime":                  func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"statusClass":                 r.getStatusClass,
		"truncate":                    func(s string, length int) string { return util.Truncate(s, length) },
		"join":                        strings.Join,
		"hasFilter":                   func() bool { return len(r.StatusFilter) > 0 },
		"filterString":                func() string { return r.getFilterString() },
		"lower":                       strings.ToLower,
		"contains":                    strings.Contains,
		"filterVulnerableUnauthority": r.filterVulnerableUnauthority,
		"filterVulnerablePrivilege":   r.filterVulnerablePrivilege,
	}).Parse(htmlTemplate)

	if err != nil {
		return fmt.Errorf("解析HTML模板失败: %v", err)
	}

	file, err := os.Create(r.OutputFile)
	if err != nil {
		return fmt.Errorf("创建HTML文件失败: %v", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, templateData); err != nil {
		return fmt.Errorf("生成HTML报告失败: %v", err)
	}

	fmt.Printf("[INFO] HTML报告已生成: %s\n", r.OutputFile)
	return nil
}

// SensitiveItem 敏感信息项（用于模板显示）
type SensitiveItem struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// prepareHTMLData 准备HTML模板数据
func (r *Reporter) prepareHTMLData() map[string]interface{} {
	filteredResults := r.filterFuzzResults()
	filteredLinks := r.filterLinks()

	sort.Slice(filteredResults, func(i, j int) bool {
		if filteredResults[i].Status == 200 && filteredResults[j].Status != 200 {
			return true
		}
		if filteredResults[i].Status != 200 && filteredResults[j].Status == 200 {
			return false
		}
		return filteredResults[i].Status < filteredResults[j].Status
	})

	sort.Slice(filteredLinks, func(i, j int) bool {
		statusI, _ := strconv.Atoi(filteredLinks[i].Status)
		statusJ, _ := strconv.Atoi(filteredLinks[j].Status)
		if statusI == 200 && statusJ != 200 {
			return true
		}
		if statusI != 200 && statusJ == 200 {
			return false
		}
		return statusI < statusJ
	})

	var sensitiveItems []SensitiveItem
	for _, info := range r.SensitiveInfo {
		// 处理各种类型的敏感信息
		for _, phone := range info.Phone {
			sensitiveItems = append(sensitiveItems, SensitiveItem{
				Type:   "手机号",
				Value:  phone,
				Source: info.Source,
			})
		}
		for _, email := range info.Email {
			sensitiveItems = append(sensitiveItems, SensitiveItem{
				Type:   "邮箱",
				Value:  email,
				Source: info.Source,
			})
		}
		for _, idcard := range info.IDcard {
			sensitiveItems = append(sensitiveItems, SensitiveItem{
				Type:   "身份证",
				Value:  idcard,
				Source: info.Source,
			})
		}
		for _, jwt := range info.JWT {
			sensitiveItems = append(sensitiveItems, SensitiveItem{
				Type:   "JWT Token",
				Value:  jwt,
				Source: info.Source,
			})
		}
		for _, key := range info.Key {
			sensitiveItems = append(sensitiveItems, SensitiveItem{
				Type:   "密钥",
				Value:  key,
				Source: info.Source,
			})
		}
		for _, password := range info.Password {
			sensitiveItems = append(sensitiveItems, SensitiveItem{
				Type:   "密码",
				Value:  password,
				Source: info.Source,
			})
		}
		for _, name := range info.Name {
			sensitiveItems = append(sensitiveItems, SensitiveItem{
				Type:   "用户名",
				Value:  name,
				Source: info.Source,
			})
		}
		for _, other := range info.Other {
			sensitiveItems = append(sensitiveItems, SensitiveItem{
				Type:   "其他",
				Value:  other,
				Source: info.Source,
			})
		}
	}

	// 分类JS文件（相关和无关）
	relatedJS, unrelatedJS := r.categorizeJSFiles()

	// 分类链接（相关和无关）- 使用过滤后的链接
	relatedLinks, unrelatedLinks := r.categorizeFilteredLinks(filteredLinks)

	// 统计信息
	stats := r.calculateStats(filteredResults)

	// 分类权限检测结果
	var vulnerableResults, safeResults []mode.AuthorityResult
	for _, result := range r.AuthorityResults {
		if result.Vulnerable {
			vulnerableResults = append(vulnerableResults, result)
		} else {
			safeResults = append(safeResults, result)
		}
	}

	return map[string]interface{}{
		"Timestamp":                  time.Now(),
		"FuzzResults":                filteredResults,
		"SensitiveInfo":              sensitiveItems,
		"RelatedJSFiles":             relatedJS,
		"UnrelatedJSFiles":           unrelatedJS,
		"RelatedLinks":               relatedLinks,
		"UnrelatedLinks":             unrelatedLinks,
		"Links":                      filteredLinks, // 保持向后兼容
		"DomainInfo":                 r.DomainInfo,
		"AuthorityResults":           r.AuthorityResults,
		"UnauthorityResults":         r.UnauthorityResults,
		"PrivilegeEscalationResults": r.PrivilegeEscalationResults,
		"ParamFuzzResults":           r.ParamFuzzResults,
		"VulnerableResults":          vulnerableResults,
		"SafeResults":                safeResults,
		"Stats":                      stats,
		"StatusFilter":               r.StatusFilter,
	}
}

// filterFuzzResults 过滤模糊测试结果
func (r *Reporter) filterFuzzResults() []mode.FuzzResult {
	if len(r.StatusFilter) == 0 {
		return r.FuzzResults
	}

	var filtered []mode.FuzzResult
	for _, result := range r.FuzzResults {
		for _, status := range r.StatusFilter {
			if result.Status == status {
				filtered = append(filtered, result)
				break
			}
		}
	}
	return filtered
}

// filterLinks 过滤链接结果
func (r *Reporter) filterLinks() []mode.Link {
	if len(r.StatusFilter) == 0 {
		return r.Links
	}

	var filtered []mode.Link
	for _, link := range r.Links {
		// 处理字符串状态码
		linkStatus, err := strconv.Atoi(link.Status)
		if err != nil {
			// 如果状态码不是数字（如"SKIPPED"或空字符串），根据过滤器决定是否包含
			// 对于特殊状态（如危险路由跳过）或空状态码，总是显示
			if link.Status == "SKIPPED" || link.Status == "" {
				filtered = append(filtered, link)
			}
			continue
		}

		for _, status := range r.StatusFilter {
			if linkStatus == status {
				filtered = append(filtered, link)
				break
			}
		}
	}
	return filtered
}

// categorizeJSFiles 分类JS文件（基于域名）
func (r *Reporter) categorizeJSFiles() ([]mode.JSFile, []mode.JSFile) {
	var related, unrelated []mode.JSFile

	// 获取目标域名（从第一个链接或JS文件的来源中提取）
	targetDomain := r.getTargetDomain()

	for _, jsFile := range r.JSFiles {
		// 基于域名判断是否为相关JS文件
		if r.isSameDomain(jsFile.Url, targetDomain) {
			related = append(related, jsFile)
		} else {
			unrelated = append(unrelated, jsFile)
		}
	}

	return related, unrelated
}

// categorizeLinks 分类链接（基于域名）
func (r *Reporter) categorizeLinks() ([]mode.Link, []mode.Link) {
	return r.categorizeFilteredLinks(r.Links)
}

// categorizeFilteredLinks 分类过滤后的链接（基于域名）
func (r *Reporter) categorizeFilteredLinks(links []mode.Link) ([]mode.Link, []mode.Link) {
	var related, unrelated []mode.Link

	targetDomain := r.getTargetDomain()

	authorityMap := make(map[string]*mode.AuthorityResult)
	for i := range r.AuthorityResults {
		authorityMap[r.AuthorityResults[i].URL] = &r.AuthorityResults[i]
	}

	unauthorityMap := make(map[string]*mode.UnauthorityResult)
	for i := range r.UnauthorityResults {
		unauthorityMap[r.UnauthorityResults[i].URL] = &r.UnauthorityResults[i]
	}

	for _, link := range links {
		if authResult, exists := authorityMap[link.Url]; exists {
			link.Status = fmt.Sprintf("%d", authResult.NoAuthStatusCode)
			link.Content = r.extractContentSummary(authResult.NoAuthResponse)
			if authResult.NoAuthStatusCode == 401 || authResult.NoAuthStatusCode == 403 || authResult.Vulnerable {
				if link.Title == "" {
					link.Title = "需要鉴权"
				} else if !strings.Contains(link.Title, "需要鉴权") {
					link.Title = link.Title + " [需要鉴权]"
				}
			}
		} else if unauthorityResult, exists := unauthorityMap[link.Url]; exists {
			link.Status = fmt.Sprintf("%d", unauthorityResult.NoAuthStatusCode)
			link.Content = r.extractContentSummary(unauthorityResult.NoAuthResponse)
			if unauthorityResult.NoAuthStatusCode == 401 || unauthorityResult.NoAuthStatusCode == 403 {
				if link.Title == "" {
					link.Title = "需要鉴权"
				} else if !strings.Contains(link.Title, "需要鉴权") {
					link.Title = link.Title + " [需要鉴权]"
				}
			}
		}

		if r.isSameDomain(link.Url, targetDomain) {
			related = append(related, link)
		} else {
			unrelated = append(unrelated, link)
		}
	}

	return related, unrelated
}

// getTargetDomain 获取目标域名
func (r *Reporter) getTargetDomain() string {
	for _, link := range r.Links {
		if link.Source == "" { // 初始URL没有来源
			if u, err := url.Parse(link.Url); err == nil {
				return u.Host
			}
		}
	}

	for _, jsFile := range r.JSFiles {
		if jsFile.Source != "" {
			if u, err := url.Parse(jsFile.Source); err == nil {
				return u.Host
			}
		}
	}

	return ""
}

// isSameDomain 判断两个URL是否属于同一域名
func (r *Reporter) isSameDomain(jsURL, targetDomain string) bool {
	if targetDomain == "" {
		return true // 如果无法确定目标域名，默认为相关
	}

	u, err := url.Parse(jsURL)
	if err != nil {
		return false
	}

	return u.Host == targetDomain
}

// hasJSSensitiveInfo 检查JS文件是否包含敏感信息
func (r *Reporter) hasJSSensitiveInfo(jsURL string) bool {
	for _, info := range r.SensitiveInfo {
		if info.Source == jsURL {
			return true
		}
	}
	return false
}

// calculateStats 计算统计信息
func (r *Reporter) calculateStats(fuzzResults []mode.FuzzResult) map[string]interface{} {
	statsMap := make(map[int]int)
	successCount := 0
	errorCount := 0

	for _, result := range fuzzResults {
		statsMap[result.Status]++
		if util.IsSuccessStatusCode(result.Status) {
			successCount++
		}
		if result.Error != "" {
			errorCount++
		}
	}

	return map[string]interface{}{
		"TotalFuzzResults":      len(fuzzResults),
		"SuccessCount":          successCount,
		"ErrorCount":            errorCount,
		"JSFilesCount":          len(r.JSFiles),
		"LinksCount":            len(r.Links),
		"SensitiveInfoCount":    len(r.SensitiveInfo),
		"ParamFuzzResultsCount": len(r.ParamFuzzResults),
		"StatusStats":           statsMap,
	}
}

// formatSizeHelper 格式化大小（支持int64和string类型）
func (r *Reporter) formatSizeHelper(size interface{}) string {
	switch v := size.(type) {
	case int64:
		return util.FormatSize(v)
	case int:
		return util.FormatSize(int64(v))
	case string:
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			return util.FormatSize(parsed)
		}
		return v
	default:
		return "unknown"
	}
}

// getStatusClass 获取状态码对应的CSS类（支持int和string类型）
func (r *Reporter) getStatusClass(status interface{}) string {
	var statusCode int
	switch v := status.(type) {
	case int:
		statusCode = v
	case string:
		if parsed, err := strconv.Atoi(v); err == nil {
			statusCode = parsed
		} else {
			return "unknown"
		}
	default:
		return "unknown"
	}

	if util.IsSuccessStatusCode(statusCode) {
		return "success"
	}
	if util.IsRedirectStatusCode(statusCode) {
		return "redirect"
	}
	if util.IsClientErrorStatusCode(statusCode) {
		return "client-error"
	}
	if util.IsServerErrorStatusCode(statusCode) {
		return "server-error"
	}
	return "unknown"
}

// getFilterString 获取过滤器字符串
func (r *Reporter) getFilterString() string {
	if len(r.StatusFilter) == 0 {
		return "all"
	}
	var strs []string
	for _, status := range r.StatusFilter {
		strs = append(strs, strconv.Itoa(status))
	}
	return strings.Join(strs, ",")
}

// filterVulnerableUnauthority 过滤出有漏洞的未授权访问检测结果
func (r *Reporter) filterVulnerableUnauthority(results []mode.UnauthorityResult) []mode.UnauthorityResult {
	var vulnerable []mode.UnauthorityResult
	for _, result := range results {
		if result.Vulnerable {
			vulnerable = append(vulnerable, result)
		}
	}
	return vulnerable
}

// filterVulnerablePrivilege 过滤出有漏洞的未授权访问检测结果
func (r *Reporter) filterVulnerablePrivilege(results []mode.PrivilegeEscalationResult) []mode.PrivilegeEscalationResult {
	var vulnerable []mode.PrivilegeEscalationResult
	for _, result := range results {
		if result.Vulnerable {
			vulnerable = append(vulnerable, result)
		}
	}
	return vulnerable
}

// extractContentSummary 从HTTP响应中提取内容摘要
func (r *Reporter) extractContentSummary(response string) string {
	if response == "" {
		return ""
	}

	parts := strings.Split(response, "\r\n\r\n")
	if len(parts) < 2 {
		return ""
	}

	body := strings.Join(parts[1:], "\r\n\r\n")
	body = strings.Trim(body, "\"")
	body = strings.ReplaceAll(body, "\\n", "\n")
	body = strings.ReplaceAll(body, "\\r", "\r")
	body = strings.ReplaceAll(body, "\\t", "\t")

	keywords := []string{
		"权限不足", "权限", "鉴权", "未授权", "禁止访问", "访问被拒绝",
		"Forbidden", "Unauthorized", "Access Denied", "Permission Denied",
		"登录", "Login", "认证", "Authentication", "授权", "Authorization",
		"错误", "Error", "异常", "Exception", "失败", "Failed",
	}

	// 查找关键词并提取周围文本
	bodyLower := strings.ToLower(body)
	for _, keyword := range keywords {
		keywordLower := strings.ToLower(keyword)
		if idx := strings.Index(bodyLower, keywordLower); idx != -1 {
			start := idx - 10
			if start < 0 {
				start = 0
			}
			end := idx + len(keyword) + 10
			if end > len(body) {
				end = len(body)
			}
			extract := strings.TrimSpace(body[start:end])
			extract = r.cleanHTML(extract)
			if len(extract) > 20 {
				return util.Truncate(extract, 20)
			}
			return extract
		}
	}

	if title := r.extractTitle(body); title != "" {
		return util.Truncate(title, 20)
	}

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(r.cleanHTML(line))
		if len(line) > 5 && !strings.HasPrefix(line, "<") {
			return util.Truncate(line, 20)
		}
	}

	return ""
}

// cleanHTML 简单清理HTML标签
func (r *Reporter) cleanHTML(text string) string {

	re := regexp.MustCompile(`<[^>]*>`)
	text = re.ReplaceAllString(text, "")
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

// extractTitle 从HTML中提取标题
func (r *Reporter) extractTitle(html string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]*)</title>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// SaveToFile 保存结果到文件
func SaveToFile(filename string, jsFiles []mode.JSFile, links []mode.Link, sensitiveInfo []mode.Info, fuzzResults []mode.FuzzResult, domainInfo []mode.DomainInfo, authorityResults []mode.AuthorityResult, unauthorityResults []mode.UnauthorityResult, privilegeEscalationResults []mode.PrivilegeEscalationResult, paramFuzzResults []mode.ParamFuzzResult, statusFilter []int) error {

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	ext := strings.ToLower(filepath.Ext(filename))
	var format string
	switch ext {
	case ".csv":
		format = "csv"
	case ".json":
		format = "json"
	case ".html", ".htm":
		format = "html"
	default:
		format = "html"
		filename += ".html"
	}

	reporter := NewReporter(jsFiles, links, sensitiveInfo, fuzzResults, domainInfo, authorityResults, unauthorityResults, privilegeEscalationResults, paramFuzzResults)
	reporter.SetStatusFilter(statusFilter)
	reporter.SetOutput(filename, format)

	return reporter.Generate()
}
