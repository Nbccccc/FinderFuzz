package crawler

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/Nbccccc/FinderFuzz/config"
	"github.com/Nbccccc/FinderFuzz/mode"
	"github.com/Nbccccc/FinderFuzz/util"
)

// PermissionChecker 统一的权限检测器，支持多种权限检测模式
type PermissionChecker struct {
	LowAuthClient              *util.HTTPClient                 // 低权限HTTP客户端
	HighAuthClient             *util.HTTPClient                 // 高权限HTTP客户端
	NoAuthClient               *util.HTTPClient                 // 无认证HTTP客户端
	TargetURLs                 []string                         // 目标URL列表
	AuthorityResults           []mode.AuthorityResult           // 权限检测结果
	UnauthorityResults         []mode.UnauthorityResult         // 未授权访问检测结果
	PrivilegeEscalationResults []mode.PrivilegeEscalationResult // 未授权访问检测结果
}

// NewPermissionChecker 创建统一权限检测器
func NewPermissionChecker(lowAuthClient, highAuthClient *util.HTTPClient, urls []string) *PermissionChecker {
	return &PermissionChecker{
		LowAuthClient:              lowAuthClient,
		HighAuthClient:             highAuthClient,
		NoAuthClient:               createNoAuthClient(),
		TargetURLs:                 urls,
		AuthorityResults:           make([]mode.AuthorityResult, 0),
		UnauthorityResults:         make([]mode.UnauthorityResult, 0),
		PrivilegeEscalationResults: make([]mode.PrivilegeEscalationResult, 0),
	}
}

// NewAuthorityChecker 创建权限检测器（向后兼容）
func NewAuthorityChecker(urls []string) *PermissionChecker {
	return &PermissionChecker{
		LowAuthClient:              util.NewHTTPClient(),
		HighAuthClient:             util.NewHTTPClient(),
		NoAuthClient:               createNoAuthClient(),
		TargetURLs:                 urls,
		AuthorityResults:           make([]mode.AuthorityResult, 0),
		UnauthorityResults:         make([]mode.UnauthorityResult, 0),
		PrivilegeEscalationResults: make([]mode.PrivilegeEscalationResult, 0),
	}
}

// NewUnauthorityChecker 创建未授权访问检测器（向后兼容）
func NewUnauthorityChecker(client *util.HTTPClient, urls []string) *PermissionChecker {
	return &PermissionChecker{
		LowAuthClient:              client,
		HighAuthClient:             client,
		NoAuthClient:               createNoAuthClient(),
		TargetURLs:                 urls,
		AuthorityResults:           make([]mode.AuthorityResult, 0),
		UnauthorityResults:         make([]mode.UnauthorityResult, 0),
		PrivilegeEscalationResults: make([]mode.PrivilegeEscalationResult, 0),
	}
}

// NewPrivilegeEscalationChecker 创建未授权访问检测器（向后兼容）
func NewPrivilegeEscalationChecker(lowAuthClient, highAuthClient *util.HTTPClient, urls []string) *PermissionChecker {
	return &PermissionChecker{
		LowAuthClient:              lowAuthClient,
		HighAuthClient:             highAuthClient,
		NoAuthClient:               createNoAuthClient(),
		TargetURLs:                 urls,
		AuthorityResults:           make([]mode.AuthorityResult, 0),
		UnauthorityResults:         make([]mode.UnauthorityResult, 0),
		PrivilegeEscalationResults: make([]mode.PrivilegeEscalationResult, 0),
	}
}

// createNoAuthClient 创建无认证的HTTP客户端
func createNoAuthClient() *util.HTTPClient {
	client := util.NewHTTPClient()
	// 清空所有认证相关的headers
	client.Headers = make(map[string]string)
	// 只保留基本的User-Agent
	client.Headers["User-Agent"] = config.DefaultUserAgent
	return client
}

// CheckAuthority 检测权限
func (pc *PermissionChecker) CheckAuthority() error {
	fmt.Printf("[INFO] 开始权限检测，共 %d 个URL\n", len(pc.TargetURLs))

	for i, url := range pc.TargetURLs {
		fmt.Printf("[INFO] 检测权限 %d/%d: %s\n", i+1, len(pc.TargetURLs), url)

		result := pc.checkAuthorityForURL(url)
		pc.AuthorityResults = append(pc.AuthorityResults, result)

		// 添加延迟避免请求过快
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("[INFO] 权限检测完成\n")
	return nil
}

// CheckUnauthority 检测未授权访问
func (pc *PermissionChecker) CheckUnauthority() error {
	fmt.Printf("[INFO] 开始未授权访问检测，共 %d 个URL\n", len(pc.TargetURLs))

	for i, url := range pc.TargetURLs {
		fmt.Printf("[INFO] 检测未授权访问 %d/%d: %s\n", i+1, len(pc.TargetURLs), url)

		result := pc.checkUnauthorityForURL(url)
		pc.UnauthorityResults = append(pc.UnauthorityResults, result)

		// 添加延迟避免请求过快
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("[INFO] 未授权访问检测完成\n")
	return nil
}

// CheckPrivilegeEscalation 执行未授权访问检测
func (pc *PermissionChecker) CheckPrivilegeEscalation() {
	fmt.Printf("[INFO] 开始未授权访问检测，共 %d 个URL\n", len(pc.TargetURLs))

	for i, url := range pc.TargetURLs {
		fmt.Printf("[INFO] 检测未授权访问 %d/%d: %s\n", i+1, len(pc.TargetURLs), url)

		result := pc.checkPrivilegeEscalationForURL(url)
		pc.PrivilegeEscalationResults = append(pc.PrivilegeEscalationResults, result)

		// 添加延迟避免请求过快
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("[INFO] 未授权访问检测完成\n")
}

// checkAuthorityForURL 检测单个URL的权限
func (pc *PermissionChecker) checkAuthorityForURL(url string) mode.AuthorityResult {
	result := mode.AuthorityResult{
		URL:        url,
		HasAuth:    false,
		NoAuth:     false,
		Vulnerable: false,
		Reason:     "",
	}

	// 使用认证请求头请求
	authResp, authBody, authReq, authRespDump, authErr := pc.makeRequestWithDump(pc.LowAuthClient, url)
	if authErr != nil {
		result.Reason = fmt.Sprintf("认证请求失败: %v", authErr)
		return result
	}
	result.AuthStatusCode = authResp.StatusCode
	result.HasAuth = true
	result.AuthRequest = authReq
	result.AuthResponse = authRespDump

	// 使用无认证请求头请求
	noAuthResp, noAuthBody, noAuthReq, noAuthRespDump, noAuthErr := pc.makeRequestWithDump(pc.NoAuthClient, url)
	if noAuthErr != nil {
		result.Reason = fmt.Sprintf("无认证请求失败: %v", noAuthErr)
		return result
	}
	result.NoAuthStatusCode = noAuthResp.StatusCode
	result.NoAuth = true
	result.NoAuthRequest = noAuthReq
	result.NoAuthResponse = noAuthRespDump

	// 分析结果
	pc.analyzeAuthority(&result, authResp, authBody, noAuthResp, noAuthBody)

	return result
}

// checkUnauthorityForURL 检测单个URL的未授权访问
func (pc *PermissionChecker) checkUnauthorityForURL(url string) mode.UnauthorityResult {
	result := mode.UnauthorityResult{
		URL:        url,
		HasAuth:    false,
		NoAuth:     false,
		Vulnerable: false,
		Reason:     "",
	}

	// 使用认证请求头请求
	authResp, authBody, authReq, authRespDump, authErr := pc.makeRequestWithDump(pc.LowAuthClient, url)
	if authErr != nil {
		result.Reason = fmt.Sprintf("认证请求失败: %v", authErr)
		return result
	}
	result.AuthStatusCode = authResp.StatusCode
	result.HasAuth = true
	result.AuthRequest = authReq
	result.AuthResponse = authRespDump

	// 使用无认证请求头请求
	noAuthResp, noAuthBody, noAuthReq, noAuthRespDump, noAuthErr := pc.makeRequestWithDump(pc.NoAuthClient, url)
	if noAuthErr != nil {
		result.Reason = fmt.Sprintf("无认证请求失败: %v", noAuthErr)
		return result
	}
	result.NoAuthStatusCode = noAuthResp.StatusCode
	result.NoAuth = true
	result.NoAuthRequest = noAuthReq
	result.NoAuthResponse = noAuthRespDump

	// 分析结果
	pc.analyzeUnauthority(&result, authResp, authBody, noAuthResp, noAuthBody)

	return result
}

// checkPrivilegeEscalationForURL 检测单个URL的未授权访问漏洞
func (pc *PermissionChecker) checkPrivilegeEscalationForURL(url string) mode.PrivilegeEscalationResult {
	result := mode.PrivilegeEscalationResult{
		URL:         url,
		HasLowAuth:  false,
		HasHighAuth: false,
		Vulnerable:  false,
		Reason:      "",
	}

	// 使用低权限客户端发送请求
	lowAuthResp, lowAuthBody, lowAuthReq, lowAuthRespDump, lowAuthErr := pc.makeRequestWithDump(pc.LowAuthClient, url)
	if lowAuthErr != nil {
		result.Reason = fmt.Sprintf("低权限请求失败: %v", lowAuthErr)
		return result
	}
	result.HasLowAuth = true
	result.LowAuthStatusCode = lowAuthResp.StatusCode
	result.LowAuthRequest = lowAuthReq
	result.LowAuthResponse = lowAuthRespDump

	// 使用高权限客户端发送请求
	highAuthResp, highAuthBody, highAuthReq, highAuthRespDump, highAuthErr := pc.makeRequestWithDump(pc.HighAuthClient, url)
	if highAuthErr != nil {
		result.Reason = fmt.Sprintf("高权限请求失败: %v", highAuthErr)
		return result
	}
	result.HasHighAuth = true
	result.HighAuthStatusCode = highAuthResp.StatusCode
	result.HighAuthRequest = highAuthReq
	result.HighAuthResponse = highAuthRespDump

	// 分析未授权访问漏洞
	pc.analyzePrivilegeEscalation(&result, lowAuthResp, lowAuthBody, highAuthResp, highAuthBody)

	return result
}

// makeRequestWithDump 发送HTTP请求并记录请求响应数据包
func (pc *PermissionChecker) makeRequestWithDump(client *util.HTTPClient, url string) (*http.Response, string, string, string, error) {
	// 创建请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", "", "", err
	}

	// 设置请求头
	for key, value := range client.Headers {
		req.Header.Set(key, value)
	}

	// 记录请求数据包
	reqDump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, "", "", "", err
	}

	// 发送请求
	resp, err := client.Client.Do(req)
	if err != nil {
		return nil, "", string(reqDump), "", err
	}
	defer resp.Body.Close()

	// 记录响应数据包
	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return resp, "", string(reqDump), "", err
	}

	// 读取响应体
	body, err := util.ReadResponseBody(resp)
	if err != nil {
		return resp, "", string(reqDump), string(respDump), err
	}

	return resp, body, string(reqDump), string(respDump), nil
}

// analyzeAuthority 分析权限检测结果
func (pc *PermissionChecker) analyzeAuthority(result *mode.AuthorityResult, authResp *http.Response, authBody string, noAuthResp *http.Response, noAuthBody string) {
	// 从配置中获取未授权关键词
	unauthorizedKeywords := config.Conf.UnauthorizedKeywords

	// 核心逻辑：检测无认证时返回401/403等未授权状态码，带认证头后返回200可以访问的情况
	// 这表明该接口需要权限才能访问，是我们要找的有权限保护的接口
	if (noAuthResp.StatusCode == 401 || noAuthResp.StatusCode == 403) && authResp.StatusCode == 200 {
		result.Vulnerable = true
		result.Reason = fmt.Sprintf("发现需要权限的接口: 无认证请求返回%d，认证请求返回%d，该接口需要权限才能访问", noAuthResp.StatusCode, authResp.StatusCode)
		return
	}

	// 检查无认证时返回其他错误状态码，但认证后可以访问的情况
	if noAuthResp.StatusCode >= 400 && authResp.StatusCode == 200 {
		result.Vulnerable = true
		result.Reason = fmt.Sprintf("发现需要权限的接口: 无认证请求返回%d，认证请求返回%d", noAuthResp.StatusCode, authResp.StatusCode)
		return
	}

	// 检查响应内容中的未授权关键词
	if noAuthResp.StatusCode == 200 {
		for _, keyword := range unauthorizedKeywords {
			if strings.Contains(noAuthBody, keyword) && authResp.StatusCode == 200 && !strings.Contains(authBody, keyword) {
				result.Vulnerable = true
				result.Reason = fmt.Sprintf("发现需要权限的接口: 无认证响应包含未授权关键词'%s'，认证后可正常访问", keyword)
				return
			}
		}
	}

	// 检查响应内容长度差异（认证后内容更丰富）
	if authResp.StatusCode == 200 && noAuthResp.StatusCode == 200 {
		if len(authBody) > 0 && len(noAuthBody) > 0 {
			lengthDiff := float64(abs(len(authBody)-len(noAuthBody))) / float64(max(len(authBody), len(noAuthBody)))
			if lengthDiff > 0.3 && len(authBody) > len(noAuthBody) { // 认证后内容更多
				result.Vulnerable = true
				result.Reason = fmt.Sprintf("发现需要权限的接口: 认证后内容更丰富 (认证请求%d字节，无认证请求%d字节)", len(authBody), len(noAuthBody))
				return
			}
		}
	}

	// 如果无认证和认证都返回相同的成功响应，说明该接口不需要权限
	if authResp.StatusCode == noAuthResp.StatusCode && authResp.StatusCode == 200 {
		result.Reason = "该接口无需权限即可访问"
		return
	}

	result.Reason = "未发现需要权限的接口特征"
}

// analyzeUnauthority 分析未授权访问检测结果
func (pc *PermissionChecker) analyzeUnauthority(result *mode.UnauthorityResult, authResp *http.Response, authBody string, noAuthResp *http.Response, noAuthBody string) {
	// 核心逻辑：检测认证请求返回200可以访问，无认证请求也返回200且内容相似的情况
	// 这表明该接口存在未授权访问漏洞

	// 首先检查认证请求是否成功
	if authResp.StatusCode != 200 {
		result.Reason = fmt.Sprintf("认证请求未成功，状态码: %d，无法进行未授权访问检测", authResp.StatusCode)
		return
	}

	// 检查无认证请求是否也返回成功状态码
	if noAuthResp.StatusCode == 200 {
		// 检查响应内容相似度
		if pc.isContentSimilar(authBody, noAuthBody) {
			result.Vulnerable = true
			result.Reason = fmt.Sprintf("发现未授权访问漏洞: 认证请求和无认证请求都返回200，且内容相似 (认证请求%d字节，无认证请求%d字节)", len(authBody), len(noAuthBody))
			return
		}

		// 内容不相似但都返回200，可能是部分未授权访问
		if len(noAuthBody) > 0 {
			result.Vulnerable = true
			result.Reason = fmt.Sprintf("发现可能的未授权访问: 认证请求和无认证请求都返回200，但内容有差异 (认证请求%d字节，无认证请求%d字节)", len(authBody), len(noAuthBody))
			return
		}
	}

	// 检查无认证请求返回其他成功状态码的情况
	if noAuthResp.StatusCode >= 200 && noAuthResp.StatusCode < 300 && noAuthResp.StatusCode != 200 {
		result.Vulnerable = true
		result.Reason = fmt.Sprintf("发现可能的未授权访问: 认证请求返回200，无认证请求返回%d", noAuthResp.StatusCode)
		return
	}

	// 检查无认证请求返回重定向的情况
	if noAuthResp.StatusCode >= 300 && noAuthResp.StatusCode < 400 {
		// 重定向可能表示需要登录，这是正常的权限保护
		result.Reason = fmt.Sprintf("接口有正常的权限保护: 认证请求返回200，无认证请求返回%d (重定向)", noAuthResp.StatusCode)
		return
	}

	// 检查无认证请求返回客户端错误的情况
	if noAuthResp.StatusCode == 401 || noAuthResp.StatusCode == 403 {
		result.Reason = fmt.Sprintf("接口有正常的权限保护: 认证请求返回200，无认证请求返回%d", noAuthResp.StatusCode)
		return
	}

	// 6. 其他情况
	result.Reason = fmt.Sprintf("未发现未授权访问漏洞: 认证请求返回%d，无认证请求返回%d", authResp.StatusCode, noAuthResp.StatusCode)
}

// analyzePrivilegeEscalation 分析未授权访问漏洞
func (pc *PermissionChecker) analyzePrivilegeEscalation(result *mode.PrivilegeEscalationResult, lowAuthResp *http.Response, lowAuthBody string, highAuthResp *http.Response, highAuthBody string) {
	// 核心逻辑：检测低权限用户能否访问高权限用户才能访问的资源

	// 如果低权限请求被拒绝（401/403），高权限请求成功（200），这表明发现了需要权限的接口
	if (lowAuthResp.StatusCode == 401 || lowAuthResp.StatusCode == 403) && highAuthResp.StatusCode == 200 {
		result.Vulnerable = true
		result.Reason = fmt.Sprintf("发现需要权限的接口: 低权限请求返回%d，高权限请求返回%d，该接口需要高权限才能访问", lowAuthResp.StatusCode, highAuthResp.StatusCode)
		return
	}

	// 如果低权限请求也能成功访问（200），且与高权限请求返回相似内容，可能存在未授权访问漏洞
	if lowAuthResp.StatusCode == 200 && highAuthResp.StatusCode == 200 {
		if pc.isContentSimilar(lowAuthBody, highAuthBody) {
			result.Vulnerable = true
			result.Reason = fmt.Sprintf("发现未授权访问漏洞: 低权限用户能够访问高权限资源 (低权限%d字节，高权限%d字节，内容相似)", len(lowAuthBody), len(highAuthBody))
			return
		}

		// 检查是否返回了不同的内容，但都是成功状态
		result.Reason = fmt.Sprintf("权限检查: 低权限和高权限都能访问，但内容不同 (低权限%d字节，高权限%d字节)", len(lowAuthBody), len(highAuthBody))
		return
	}

	// 其他情况分析
	if lowAuthResp.StatusCode >= 400 && highAuthResp.StatusCode >= 400 {
		result.Reason = fmt.Sprintf("两种权限都无法访问: 低权限返回%d，高权限返回%d", lowAuthResp.StatusCode, highAuthResp.StatusCode)
	} else if lowAuthResp.StatusCode == 200 && highAuthResp.StatusCode >= 400 {
		result.Reason = fmt.Sprintf("异常情况: 低权限请求成功(%d)，高权限请求失败(%d)", lowAuthResp.StatusCode, highAuthResp.StatusCode)
	} else {
		result.Reason = fmt.Sprintf("状态码对比: 低权限返回%d，高权限返回%d", lowAuthResp.StatusCode, highAuthResp.StatusCode)
	}
}

// isContentSimilar 使用Jaccard相似度检查两个响应内容是否相似
func (pc *PermissionChecker) isContentSimilar(content1, content2 string) bool {
	// 如果两个内容都为空，认为相似
	if len(content1) == 0 && len(content2) == 0 {
		return true
	}

	// 如果其中一个为空，另一个不为空，认为不相似
	if len(content1) == 0 || len(content2) == 0 {
		return false
	}

	// 转换为小写进行比较
	content1Lower := strings.ToLower(content1)
	content2Lower := strings.ToLower(content2)

	// 如果内容完全相同
	if content1Lower == content2Lower {
		return true
	}

	// 使用Jaccard相似度算法
	// 将内容按空格分词，创建词汇集合
	words1 := strings.Fields(content1Lower)
	words2 := strings.Fields(content2Lower)

	// 创建词汇集合
	set1 := make(map[string]bool)
	set2 := make(map[string]bool)

	for _, word := range words1 {
		// 过滤掉过短的词汇
		if len(word) >= 2 {
			set1[word] = true
		}
	}

	for _, word := range words2 {
		// 过滤掉过短的词汇
		if len(word) >= 2 {
			set2[word] = true
		}
	}

	// 如果两个集合都为空，认为相似
	if len(set1) == 0 && len(set2) == 0 {
		return true
	}

	// 计算交集大小
	intersection := 0
	for word := range set1 {
		if set2[word] {
			intersection++
		}
	}

	// 计算并集大小
	union := len(set1) + len(set2) - intersection

	// 计算Jaccard相似度
	jaccardSimilarity := float64(intersection) / float64(union)

	// 设置相似度阈值为0.3（可根据实际情况调整）
	return jaccardSimilarity >= 0.3
}

// GetResults 获取权限检测结果（向后兼容）
func (pc *PermissionChecker) GetResults() []mode.AuthorityResult {
	return pc.AuthorityResults
}

// GetAuthorityResults 获取权限检测结果
func (pc *PermissionChecker) GetAuthorityResults() []mode.AuthorityResult {
	return pc.AuthorityResults
}

// GetUnauthorityResults 获取未授权访问检测结果
func (pc *PermissionChecker) GetUnauthorityResults() []mode.UnauthorityResult {
	return pc.UnauthorityResults
}

// GetPrivilegeEscalationResults 获取未授权访问检测结果
func (pc *PermissionChecker) GetPrivilegeEscalationResults() []mode.PrivilegeEscalationResult {
	return pc.PrivilegeEscalationResults
}

// abs 计算绝对值
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// max 计算最大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
