package crawler

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Nbccccc/FinderFuzz/cmd"
	"github.com/Nbccccc/FinderFuzz/config"
	"github.com/Nbccccc/FinderFuzz/mode"
	"github.com/Nbccccc/FinderFuzz/result"
	"github.com/Nbccccc/FinderFuzz/util"
)

// Run 运行爬虫和模糊测试的主入口函数
func Run() error {
	// 解析命令行参数
	args := cmd.ParseArgs()

	// 显示帮助信息
	if args.Help {
		cmd.ShowHelp()
		return nil
	}

	// 验证必要参数
	if args.URL == "" && args.URLFile == "" {
		return fmt.Errorf("必须指定目标URL (-u) 或URL文件 (-uf)")
	}

	// 加载配置
	if args.Config {
		// 使用YAML配置文件
		if err := config.LoadConfig(args.ConfigFile); err != nil {
			return fmt.Errorf("加载配置失败: %v", err)
		}
	} else {
		// 使用默认配置
		config.InitConfig()
	}

	// 应用命令行参数到配置
	applyArgsToConfig(args)

	// 显示配置信息
	showConfig(args)

	// 获取目标URL列表
	targetURLs, err := getTargetURLs(args)
	if err != nil {
		return fmt.Errorf("获取目标URL失败: %v", err)
	}

	// 处理每个目标URL
	for i, targetURL := range targetURLs {
		fmt.Printf("\n[INFO] 处理目标 %d/%d: %s\n", i+1, len(targetURLs), targetURL)

		if err := processSingleTarget(targetURL, args); err != nil {
			fmt.Printf("[ERROR] 处理目标失败: %v\n", err)
			continue
		}
	}

	fmt.Printf("\n[INFO] 所有目标处理完成\n")
	return nil
}

// applyArgsToConfig 将命令行参数应用到配置
func applyArgsToConfig(args *cmd.Args) {
	// 重新初始化Headers map以清除之前的状态
	config.Conf.Headers = make(map[string]string)

	// 处理从文件读取的请求头
	if args.ReadHeaders != "" {
		headers, err := util.ReadHeadersFromFile(args.ReadHeaders)
		if err != nil {
			fmt.Printf("[ERROR] 读取headers文件失败: %v\n", err)
			os.Exit(1)
		}
		// 将文件中的headers合并到配置中
		for key, value := range headers {
			config.Conf.Headers[key] = value
		}
		fmt.Printf("[INFO] 从文件加载了 %d 个请求头\n", len(headers))
	} else {
		// 只有在没有使用--read-headers时才处理单个参数
		if args.UserAgent != "" {
			config.Conf.Headers["User-Agent"] = args.UserAgent
		}

		if args.Cookie != "" {
			config.Conf.Headers["Cookie"] = args.Cookie
		}
	}

	if args.Proxy != "" {
		config.Conf.Proxy = args.Proxy
	}

	if args.Timeout > 0 {
		config.Conf.Timeout = args.Timeout * 1000 // 将秒转换为毫秒
	}

	if args.Thread > 0 {
		config.Conf.Thread = args.Thread
	}

	if args.Max > 0 {
		config.Conf.Max = args.Max
	}

	// 设置模糊测试模式
	if args.FuzzMode > 0 {
		config.SetFuzzNum(args.FuzzMode)
	}

	// 模式开关现在通过命令行参数控制，不再需要设置配置字段
}

// showConfig 显示配置信息
func showConfig(args *cmd.Args) {
	fmt.Printf("[INFO] 配置信息:\n")
	fmt.Printf("  - 线程数: %d\n", config.Conf.Thread)
	fmt.Printf("  - 超时时间: %dms\n", config.Conf.Timeout)
	fmt.Printf("  - 最大爬取数: %d\n", config.Conf.Max)
	fmt.Printf("  - 爬取模式: %s\n", getModeDisplayName(args.Mode))
	fmt.Printf("  - 代理: %s\n", getProxyInfo())
	fmt.Printf("  - 输出文件: %s\n", getOutputInfo(args))
	fmt.Printf("  - 状态码过滤: %s\n", getStatusFilterInfo(args))
	fmt.Printf("  - 模糊测试: %s\n", getFuzzInfo(args))
	fmt.Printf("  - 鉴权接口FUZZ: %s\n", getAuthorityFuzzInfo(args))
	fmt.Printf("  - 未授权访问检测: %s\n", getUnauthorityFuzzInfo(args))
	fmt.Printf("  - 参数模糊测试: %s\n", getParamFuzzInfo(args))
}

// getModeDisplayName 获取模式的中文显示名称
func getModeDisplayName(mode string) string {
	switch mode {
	case "normal":
		return "正常抓取"
	case "thorough":
		return "深入抓取"
	case "security":
		return "安全深入抓取"
	default:
		return "正常抓取"
	}
}

// getProxyInfo 获取代理信息
func getProxyInfo() string {
	if config.Conf.Proxy == "" {
		return "无"
	}
	return config.Conf.Proxy
}

// getOutputInfo 获取输出信息
func getOutputInfo(args *cmd.Args) string {
	if args.Output == "" {
		return "控制台输出"
	}
	return args.Output
}

// getStatusFilterInfo 获取状态码过滤信息
func getStatusFilterInfo(args *cmd.Args) string {
	if args.StatusCode == "" {
		return "全部"
	}
	return args.StatusCode
}

// getFuzzInfo 获取模糊测试信息
func getFuzzInfo(args *cmd.Args) string {
	if args.Fuzz {
		return "启用"
	}
	return "禁用"
}

// getAuthorityFuzzInfo 获取权限检测信息
func getAuthorityFuzzInfo(args *cmd.Args) string {
	if args.AuthorityFuzz {
		return "启用"
	}
	return "禁用"
}

// getUnauthorityFuzzInfo 获取未授权访问检测信息
func getUnauthorityFuzzInfo(args *cmd.Args) string {
	if args.UnauthorityFuzz {
		return "启用"
	}
	return "禁用"
}

// getParamFuzzInfo 获取参数模糊测试信息
func getParamFuzzInfo(args *cmd.Args) string {
	if args.ParamFuzz {
		return "启用"
	}
	return "禁用"
}

// getTargetURLs 获取目标URL列表
func getTargetURLs(args *cmd.Args) ([]string, error) {
	var urls []string

	// 从命令行参数获取URL
	if args.URL != "" {
		if !util.IsValidURL(args.URL) {
			return nil, fmt.Errorf("无效的URL: %s", args.URL)
		}
		urls = append(urls, args.URL)
	}

	// 从文件获取URL
	if args.URLFile != "" {
		fileURLs, err := util.ReadLines(args.URLFile)
		if err != nil {
			return nil, fmt.Errorf("读取URL文件失败: %v", err)
		}

		for _, url := range fileURLs {
			url = strings.TrimSpace(url)
			if url != "" && !strings.HasPrefix(url, "#") {
				if !util.IsValidURL(url) {
					fmt.Printf("[WARN] 跳过无效URL: %s\n", url)
					continue
				}
				urls = append(urls, url)
			}
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("未找到有效的目标URL")
	}

	return util.RemoveDuplicates(urls), nil
}

// processSingleTarget 处理单个目标
func processSingleTarget(targetURL string, args *cmd.Args) error {
	startTime := time.Now()

	// 重置进度计数器
	config.ResetProgress()
	config.ResetFuzzNum()

	// 创建爬虫
	maxDepth := getMaxDepth(args.Mode)
	crawler := NewCrawler(targetURL, maxDepth)

	// 配置HTTP客户端
	// 在双权限头模式下，爬虫应该使用低权限头进行爬取，这样才能发现需要权限的接口
	if args.HighHeaders != "" && args.ReadHeaders != "" {
		// 双权限头模式：使用低权限头进行爬取
		configureHTTPClientWithHeaders(crawler.HTTPClient, args, args.ReadHeaders)
	} else {
		// 传统模式：使用默认配置
		configureHTTPClient(crawler.HTTPClient, args)
	}

	// 开始爬取
	fmt.Printf("[INFO] 开始爬取...\n")
	if err := crawler.Start(); err != nil {
		return fmt.Errorf("爬取失败: %v", err)
	}

	// 模糊测试
	if args.Fuzz {
		fmt.Printf("[INFO] 开始模糊测试...\n")
		fuzzer := NewFuzzer(targetURL, crawler)
		// 在双权限头模式下，模糊测试也应该使用低权限头
		if args.HighHeaders != "" && args.ReadHeaders != "" {
			// 双权限头模式：使用低权限头进行模糊测试
			configureHTTPClientWithHeaders(fuzzer.HTTPClient, args, args.ReadHeaders)
		} else {
			// 传统模式：使用默认配置
			configureHTTPClient(fuzzer.HTTPClient, args)
		}

		// 设置BaseDir（如果指定了）
		if args.BaseDir != "" {
			fuzzer.SetBaseDir(args.BaseDir)
		}

		if err := fuzzer.StartFuzzing(); err != nil {
			return fmt.Errorf("模糊测试失败: %v", err)
		}
	}

	// 获取结果
	jsFiles, links, sensitiveInfo, fuzzResults, domainInfo := crawler.GetResults()

	// 权限检测
	var authorityResults []mode.AuthorityResult
	var unauthorityResults []mode.UnauthorityResult

	if args.AuthorityFuzz {
		// 收集需要权限检测的URL（只检测那些可能需要鉴权的接口）
		var urlsToCheck []string

		// 先对所有URL进行初步检测，找出可能需要鉴权的接口
		urlsToCheck = getURLsRequiringAuthCheck(links, fuzzResults, args)

		if len(urlsToCheck) > 0 {
			// 检查是否有高权限头文件，决定使用哪种检测模式
			if args.HighHeaders != "" {
				// 双权限头检测模式（低权限 vs 高权限）
				fmt.Printf("[INFO] 开始权限检测（双权限头模式）...\n")

				// 创建低权限客户端
				lowAuthClient := util.NewHTTPClient()
				configureHTTPClientWithHeaders(lowAuthClient, args, args.ReadHeaders)

				// 创建高权限客户端
				highAuthClient := util.NewHTTPClient()
				configureHTTPClientWithHeaders(highAuthClient, args, args.HighHeaders)

				// 执行双权限头检测，结果存储在authorityResults中
				privilegeChecker := NewPrivilegeEscalationChecker(lowAuthClient, highAuthClient, urlsToCheck)
				privilegeChecker.CheckPrivilegeEscalation()
				{
					// 将未授权访问检测结果转换为权限检测结果格式
					privilegeResults := privilegeChecker.GetPrivilegeEscalationResults()
					for _, result := range privilegeResults {
						authorityResult := mode.AuthorityResult{
							URL:              result.URL,
							HasAuth:          result.HasHighAuth,
							NoAuth:           result.HasLowAuth,
							AuthStatusCode:   result.HighAuthStatusCode,
							NoAuthStatusCode: result.LowAuthStatusCode,
							Vulnerable:       result.Vulnerable,
							Reason:           result.Reason,
							AuthRequest:      result.HighAuthRequest,
							AuthResponse:     result.HighAuthResponse,
							NoAuthRequest:    result.LowAuthRequest,
							NoAuthResponse:   result.LowAuthResponse,
						}
						authorityResults = append(authorityResults, authorityResult)
					}
				}
			} else {
				// 传统权限检测模式（无认证 vs 有认证）
				fmt.Printf("[INFO] 开始权限检测...\n")

				authorityChecker := NewAuthorityChecker(urlsToCheck)
				// 配置认证HTTP客户端
				configureHTTPClient(authorityChecker.LowAuthClient, args)

				if err := authorityChecker.CheckAuthority(); err != nil {
					fmt.Printf("[WARN] 权限检测失败: %v\n", err)
				} else {
					authorityResults = authorityChecker.GetResults()
				}
			}
		} else {
			fmt.Printf("[INFO] 没有找到可检测的URL\n")
		}
	}

	// 未授权访问检测
	if args.UnauthorityFuzz {
		// 收集需要未授权访问检测的URL（只检测那些可能需要鉴权的接口）
		var urlsToCheck []string

		// 先对所有URL进行初步检测，找出可能需要鉴权的接口
		urlsToCheck = getURLsRequiringAuthCheck(links, fuzzResults, args)

		if len(urlsToCheck) > 0 {
			// 检查是否有高权限头文件，决定使用哪种检测模式
			if args.HighHeaders != "" {
				// 双权限头检测模式（低权限 vs 高权限）
				fmt.Printf("[INFO] 开始未授权访问检测（双权限头模式）...\n")

				// 创建低权限客户端
				lowAuthClient := util.NewHTTPClient()
				configureHTTPClientWithHeaders(lowAuthClient, args, args.ReadHeaders)

				// 创建高权限客户端
				highAuthClient := util.NewHTTPClient()
				configureHTTPClientWithHeaders(highAuthClient, args, args.HighHeaders)

				// 执行双权限头检测，结果存储在unauthorityResults中
				privilegeChecker := NewPrivilegeEscalationChecker(lowAuthClient, highAuthClient, urlsToCheck)
				privilegeChecker.CheckPrivilegeEscalation()
				{
					// 将未授权访问检测结果转换为未授权访问检测结果格式
					// 在双权限头模式下，我们将高权限作为"认证"，低权限作为"无认证"
					// 但只有当确实存在未授权访问漏洞时才转换
					privilegeResults := privilegeChecker.GetPrivilegeEscalationResults()
					for _, result := range privilegeResults {
						// 过滤掉正常的权限控制情况
						// 如果低权限返回401/403而高权限返回200，这是正常的权限保护，不是未授权访问漏洞
						if result.Vulnerable && !isNormalPermissionControl(result) {
							unauthorityResult := mode.UnauthorityResult{
								URL:              result.URL,
								HasAuth:          result.HasHighAuth,
								NoAuth:           result.HasLowAuth,
								AuthStatusCode:   result.HighAuthStatusCode, // 高权限状态码作为认证状态码
								NoAuthStatusCode: result.LowAuthStatusCode,  // 低权限状态码作为无认证状态码
								Vulnerable:       result.Vulnerable,
								Reason:           result.Reason,
								AuthRequest:      result.HighAuthRequest,
								AuthResponse:     result.HighAuthResponse,
								NoAuthRequest:    result.LowAuthRequest,
								NoAuthResponse:   result.LowAuthResponse,
							}
							unauthorityResults = append(unauthorityResults, unauthorityResult)
						}
					}
				}
			} else {
				// 传统未授权访问检测模式（有认证 vs 无认证）
				fmt.Printf("[INFO] 开始未授权访问检测...\n")

				// 创建带认证的HTTP客户端
				client := util.NewHTTPClient()
				configureHTTPClient(client, args)
				unauthorityChecker := NewUnauthorityChecker(client, urlsToCheck)

				if err := unauthorityChecker.CheckUnauthority(); err != nil {
					fmt.Printf("[WARN] 未授权访问检测失败: %v\n", err)
				} else {
					unauthorityResults = unauthorityChecker.GetUnauthorityResults()
				}
			}
		} else {
			fmt.Printf("[INFO] 没有找到可检测的URL\n")
		}
	}

	// 参数模糊测试
	var paramFuzzResults []mode.ParamFuzzResult
	if args.ParamFuzz {
		fmt.Printf("[INFO] 开始参数模糊测试...\n")

		// 创建参数模糊测试器
		paramFuzzer := NewParamFuzzer(targetURL, crawler)

		// 执行参数模糊测试
		if err := paramFuzzer.StartParamFuzzing(); err != nil {
			fmt.Printf("[WARN] 参数模糊测试失败: %v\n", err)
		} else {
			paramFuzzResults = paramFuzzer.GetResults()
		}
	}

	// 显示结果统计
	showResults(jsFiles, links, sensitiveInfo, fuzzResults, domainInfo, authorityResults, unauthorityResults, paramFuzzResults, time.Since(startTime))

	// 保存结果
	if args.Output != "" {
		statusFilter := parseStatusFilter(args.StatusCode)
		if err := result.SaveToFile(args.Output, jsFiles, links, sensitiveInfo, fuzzResults, domainInfo, authorityResults, unauthorityResults, []mode.PrivilegeEscalationResult{}, paramFuzzResults, statusFilter); err != nil {
			return fmt.Errorf("保存结果失败: %v", err)
		}
	} else {
		// 控制台输出
		showConsoleResults(jsFiles, links, sensitiveInfo, fuzzResults, domainInfo, authorityResults, unauthorityResults, paramFuzzResults, args)
	}

	return nil
}

// isNormalPermissionControl 判断是否为正常的权限控制情况
// 如果低权限返回401/403而高权限返回200，这是正常的权限保护，不是未授权访问漏洞
func isNormalPermissionControl(result mode.PrivilegeEscalationResult) bool {
	// 检查是否为"发现需要权限的接口"的情况
	if strings.Contains(result.Reason, "发现需要权限的接口") {
		return true
	}

	// 检查状态码组合：低权限401/403 + 高权限200 = 正常权限控制
	if (result.LowAuthStatusCode == 401 || result.LowAuthStatusCode == 403) && result.HighAuthStatusCode == 200 {
		return true
	}

	return false
}

// getMaxDepth 根据模式获取最大深度
func getMaxDepth(mode string) int {
	switch mode {
	case "normal":
		return 1 // -m 1: 深度0(起始URL) + 深度1(直接发现的链接)
	case "thorough":
		return 2 // -m 2: 深度0 + 深度1 + 深度2
	case "security":
		return 3 // -m 3: 深度0 + 深度1 + 深度2 + 深度3
	default:
		return 1
	}
}

// configureHTTPClient 配置HTTP客户端
func configureHTTPClient(client *util.HTTPClient, args *cmd.Args) {
	// 设置头部
	for key, value := range config.Conf.Headers {
		client.SetHeader(key, value)
	}

	// 设置代理
	if config.Conf.Proxy != "" {
		client.SetProxy(config.Conf.Proxy)
	}

	// 设置超时
	client.SetTimeout(time.Duration(config.Conf.Timeout) * time.Millisecond)
}

// getURLsRequiringAuthCheck 获取需要权限检测的URL列表
// 只返回那些在默认/低权限访问时返回401、403或显示需要鉴权的接口
func getURLsRequiringAuthCheck(links []mode.Link, fuzzResults []mode.FuzzResult, args *cmd.Args) []string {
	var candidateURLs []string
	var urlsRequiringAuth []string

	// 收集所有候选URL
	for _, link := range links {
		if util.IsValidURL(link.Url) {
			candidateURLs = append(candidateURLs, link.Url)
		}
	}

	for _, fuzzResult := range fuzzResults {
		if util.IsValidURL(fuzzResult.URL) {
			candidateURLs = append(candidateURLs, fuzzResult.URL)
		}
	}

	// 去重
	candidateURLs = util.RemoveDuplicates(candidateURLs)

	// 过滤危险路由
	candidateURLs = util.FilterDangerousRoutes(candidateURLs)

	// 如果是未授权访问检测模式，返回所有候选URL进行检测
	if args.UnauthorityFuzz {
		fmt.Printf("[INFO] 未授权访问检测模式：将检测所有 %d 个URL\n", len(candidateURLs))
		return candidateURLs
	}

	// 创建用于初步检测的客户端 - 始终使用无认证客户端进行初步检测
	testClient := util.NewHTTPClient()
	// 只设置基本的User-Agent，不添加任何认证头
	testClient.Headers = make(map[string]string)
	testClient.Headers["User-Agent"] = config.DefaultUserAgent

	// 设置代理和超时
	if config.Conf.Proxy != "" {
		testClient.SetProxy(config.Conf.Proxy)
	}
	testClient.SetTimeout(time.Duration(config.Conf.Timeout) * time.Millisecond)

	fmt.Printf("[INFO] 正在初步检测 %d 个URL，筛选需要鉴权的接口...\n", len(candidateURLs))

	// 对每个URL进行初步检测
	for i, url := range candidateURLs {
		fmt.Printf("[INFO] 初步检测 %d/%d: %s\n", i+1, len(candidateURLs), url)

		resp, err := testClient.Get(url)
		if err != nil {
			// 请求失败，跳过
			continue
		}

		// 检查状态码是否表明需要鉴权
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			urlsRequiringAuth = append(urlsRequiringAuth, url)
			fmt.Printf("[INFO] 发现需要鉴权的接口: %s (状态码: %d)\n", url, resp.StatusCode)
		} else {
			// 检查响应内容是否包含需要鉴权的关键词
			body, err := util.ReadResponseBody(resp)
			if err == nil {
				// 检查是否包含未授权关键词
				for _, keyword := range config.Conf.UnauthorizedKeywords {
					if strings.Contains(strings.ToLower(body), strings.ToLower(keyword)) {
						urlsRequiringAuth = append(urlsRequiringAuth, url)
						fmt.Printf("[INFO] 发现需要鉴权的接口: %s (包含关键词: %s)\n", url, keyword)
						break
					}
				}
			}
		}

		// 添加延迟避免请求过快
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("[INFO] 初步检测完成，发现 %d 个需要鉴权的接口\n", len(urlsRequiringAuth))
	return urlsRequiringAuth
}



// configureHTTPClientWithHeaders 配置HTTP客户端并添加指定的请求头文件
func configureHTTPClientWithHeaders(client *util.HTTPClient, args *cmd.Args, headersFile string) {
	// 在双权限头模式下，不使用config.Conf.Headers，直接使用指定的头文件
	if args.HighHeaders != "" && args.ReadHeaders != "" {
		// 双权限头模式：只设置代理和超时，不设置config.Conf.Headers中的头部
		if config.Conf.Proxy != "" {
			client.SetProxy(config.Conf.Proxy)
		}
		client.SetTimeout(time.Duration(config.Conf.Timeout) * time.Millisecond)
	} else {
		// 传统模式：先进行基础配置
		configureHTTPClient(client, args)
	}

	// 读取并设置指定的请求头文件
	if headersFile != "" {
		headers, err := util.ReadHeadersFromFile(headersFile)
		if err != nil {
			fmt.Printf("[WARN] 读取请求头文件失败: %v\n", err)
			return
		}

		for key, value := range headers {
			client.SetHeader(key, value)
		}
	}
}

// showResults 显示结果统计
func showResults(jsFiles []mode.JSFile, links []mode.Link, sensitiveInfo []mode.Info, fuzzResults []mode.FuzzResult, domainInfo []mode.DomainInfo, authorityResults []mode.AuthorityResult, unauthorityResults []mode.UnauthorityResult, paramFuzzResults []mode.ParamFuzzResult, duration time.Duration) {
	fmt.Printf("\n[INFO] 扫描完成，耗时: %v\n", duration)
	fmt.Printf("[INFO] 结果统计:\n")
	fmt.Printf("  - JS文件: %d个\n", len(jsFiles))
	fmt.Printf("  - 链接: %d个\n", len(links))
	fmt.Printf("  - 敏感信息: %d个\n", len(sensitiveInfo))
	fmt.Printf("  - 域名信息: %d个\n", len(domainInfo))
	fmt.Printf("  - 模糊测试结果: %d个\n", len(fuzzResults))
	fmt.Printf("  - 权限检测结果: %d个\n", len(authorityResults))
	fmt.Printf("  - 未授权访问检测结果: %d个\n", len(unauthorityResults))
	fmt.Printf("  - 参数模糊测试结果: %d个\n", len(paramFuzzResults))

	// 统计成功的模糊测试结果
	successCount := 0
	for _, result := range fuzzResults {
		if util.IsSuccessStatusCode(result.Status) {
			successCount++
		}
	}
	if len(fuzzResults) > 0 {
		fmt.Printf("  - 成功响应: %d个 (%.1f%%)\n", successCount, float64(successCount)/float64(len(fuzzResults))*100)
	}

	// 统计权限检测漏洞
	vulnerableCount := 0
	for _, result := range authorityResults {
		if result.Vulnerable {
			vulnerableCount++
		}
	}
	if len(authorityResults) > 0 {
		fmt.Printf("  - 权限检测发现漏洞: %d个 (%.1f%%)\n", vulnerableCount, float64(vulnerableCount)/float64(len(authorityResults))*100)
	}

	// 统计未授权访问漏洞
	unauthorityVulnerableCount := 0
	for _, result := range unauthorityResults {
		if result.Vulnerable {
			unauthorityVulnerableCount++
		}
	}
	if len(unauthorityResults) > 0 {
		fmt.Printf("  - 未授权访问发现漏洞: %d个 (%.1f%%)\n", unauthorityVulnerableCount, float64(unauthorityVulnerableCount)/float64(len(unauthorityResults))*100)
	}

	// 统计参数模糊测试成功结果
	paramSuccessCount := 0
	for _, result := range paramFuzzResults {
		paramSuccessCount += len(result.SuccessfulParams)
	}
	if len(paramFuzzResults) > 0 {
		fmt.Printf("  - 参数模糊测试发现参数: %d个\n", paramSuccessCount)
	}

}

// parseStatusFilter 解析状态码过滤器
func parseStatusFilter(statusCode string) []int {
	if statusCode == "" || statusCode == "all" {
		return []int{}
	}

	var filters []int
	parts := strings.Split(statusCode, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if code, err := strconv.Atoi(part); err == nil {
			filters = append(filters, code)
		}
	}
	return filters
}

// showConsoleResults 显示控制台结果
func showConsoleResults(jsFiles []mode.JSFile, links []mode.Link, sensitiveInfo []mode.Info, fuzzResults []mode.FuzzResult, domainInfo []mode.DomainInfo, authorityResults []mode.AuthorityResult, unauthorityResults []mode.UnauthorityResult, paramFuzzResults []mode.ParamFuzzResult, args *cmd.Args) {
	statusFilter := parseStatusFilter(args.StatusCode)

	// 显示模糊测试结果
	if len(fuzzResults) > 0 {
		fmt.Printf("\n[INFO] 模糊测试结果:\n")
		for _, result := range fuzzResults {
			// 应用状态码过滤
			if len(statusFilter) > 0 {
				matched := false
				for _, status := range statusFilter {
					if result.Status == status {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			fmt.Printf("  [%d] %s %s (%d) - %s\n",
				result.Status, result.Method, result.URL,
				result.Size, result.FuzzType)
		}
	}

	// 显示敏感信息
	if len(sensitiveInfo) > 0 {
		fmt.Printf("\n[INFO] 敏感信息:\n")
		for _, info := range sensitiveInfo {
			// 显示敏感信息
			if len(info.Phone) > 0 {
				for _, phone := range info.Phone {
					fmt.Printf("  [phone] %s - %s\n", phone, info.Source)
				}
			}
			if len(info.Email) > 0 {
				for _, email := range info.Email {
					fmt.Printf("  [email] %s - %s\n", email, info.Source)
				}
			}
			if len(info.IDcard) > 0 {
				for _, idcard := range info.IDcard {
					fmt.Printf("  [idcard] %s - %s\n", idcard, info.Source)
				}
			}
			if len(info.JWT) > 0 {
				for _, jwt := range info.JWT {
					fmt.Printf("  [jwt] %s - %s\n", jwt, info.Source)
				}
			}
			if len(info.Key) > 0 {
				for _, key := range info.Key {
					fmt.Printf("  [key] %s - %s\n", key, info.Source)
				}
			}
			if len(info.Password) > 0 {
				for _, password := range info.Password {
					fmt.Printf("  [password] %s - %s\n", password, info.Source)
				}
			}
			if len(info.Name) > 0 {
				for _, name := range info.Name {
					fmt.Printf("  [name] %s - %s\n", name, info.Source)
				}
			}
			if len(info.Other) > 0 {
				for _, other := range info.Other {
					fmt.Printf("  [other] %s - %s\n", other, info.Source)
				}
			}
		}
	}

	// 显示域名信息
	if len(domainInfo) > 0 {
		fmt.Printf("\n[INFO] 域名信息:\n")
		for _, domain := range domainInfo {
			fmt.Printf("  - %s (%s) - %s [来源: %s]\n", domain.Domain, domain.Type, domain.CloudType, domain.Source)
		}
	}

	// 显示JS文件（仅显示包含API的）
	if len(jsFiles) > 0 {
		fmt.Printf("\n[INFO] JS文件 (包含API):\n")
		for _, jsFile := range jsFiles {
			if len(jsFile.APIs) > 0 {
				fmt.Printf("  [%s] %s (%s) - %d个API\n",
					jsFile.Status, jsFile.Url, jsFile.Size, len(jsFile.APIs))
				for _, api := range jsFile.APIs {
					fmt.Printf("    - %s\n", api)
				}
			}
		}
	}

	// 显示权限检测结果
	if len(authorityResults) > 0 {
		fmt.Printf("\n[INFO] 权限检测结果:\n")
		for _, result := range authorityResults {
			vulnStatus := "正常"
			if result.Vulnerable {
				vulnStatus = "发现漏洞"
			}
			fmt.Printf("  [%s] %s - 认证:%d 无认证:%d - %s\n",
				vulnStatus, result.URL, result.AuthStatusCode, result.NoAuthStatusCode, result.Reason)
		}
	}

	// 显示未授权访问检测结果
	if len(unauthorityResults) > 0 {
		fmt.Printf("\n[INFO] 未授权访问检测结果:\n")
		for _, result := range unauthorityResults {
			vulnStatus := "正常"
			if result.Vulnerable {
				vulnStatus = "发现漏洞"
			}
			fmt.Printf("  [%s] %s - 认证:%d 无认证:%d - %s\n",
				vulnStatus, result.URL, result.AuthStatusCode, result.NoAuthStatusCode, result.Reason)
		}
	}

	// 显示参数模糊测试结果
	if len(paramFuzzResults) > 0 {
		fmt.Printf("\n[INFO] 参数模糊测试结果:\n")
		for _, result := range paramFuzzResults {
			fmt.Printf("  [%s] %s - 原始状态:%d\n", result.Method, result.URL, result.OriginalStatus)
			if len(result.ErrorHints) > 0 {
				fmt.Printf("    错误提示: %s\n", strings.Join(result.ErrorHints, ", "))
			}
			if len(result.SuccessfulParams) > 0 {
				fmt.Printf("    发现参数: %s\n", strings.Join(result.SuccessfulParams, ", "))
				for _, testResult := range result.TestResults {
					if testResult.Success {
						fmt.Printf("      - %s: %s (状态:%d, 大小:%d)\n",
							testResult.ParamName, testResult.ParamValue, testResult.StatusCode, testResult.ResponseSize)
					}
				}
			} else {
				fmt.Printf("    未发现有效参数\n")
			}
		}
	}

}

// CheckDependencies 检查依赖
func CheckDependencies() error {
	// 检查配置文件是否存在
	if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
		fmt.Printf("[WARN] 配置文件不存在，将使用默认配置\n")
	}

	return nil
}
