package crawler

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"

	"github.com/Nbccccc/FinderFuzz/config"
	"github.com/Nbccccc/FinderFuzz/mode"
	"github.com/Nbccccc/FinderFuzz/util"
)

// Crawler 网页爬虫结构体，负责爬取网页内容并提取敏感信息
type Crawler struct {
	HTTPClient       *util.HTTPClient       // HTTP客户端
	Visited          map[string]bool        // 已访问的URL记录
	JSFiles          []mode.JSFile          // 发现的JS文件列表
	Links            []mode.Link            // 发现的链接列表
	SensitiveInfo    []mode.Info            // 提取的敏感信息
	FuzzResults      []mode.FuzzResult      // 模糊测试结果
	DomainInfo       []mode.DomainInfo      // 域名信息
	ParamFuzzResults []mode.ParamFuzzResult // 参数模糊测试结果
	mu               sync.RWMutex           // 读写锁，保证并发安全
	Depth            int                    // 当前爬取深度
	MaxDepth         int                    // 最大爬取深度
	BaseURL          string                 // 基础URL
	Domain           string                 // 目标域名
}

// NewCrawler 创建新的爬虫实例
func NewCrawler(baseURL string, maxDepth int) *Crawler {
	return &Crawler{
		HTTPClient:       util.NewHTTPClient(),
		Visited:          make(map[string]bool),
		JSFiles:          make([]mode.JSFile, 0),
		Links:            make([]mode.Link, 0),
		SensitiveInfo:    make([]mode.Info, 0),
		FuzzResults:      make([]mode.FuzzResult, 0),
		DomainInfo:       make([]mode.DomainInfo, 0),
		ParamFuzzResults: make([]mode.ParamFuzzResult, 0),
		Depth:            0,
		MaxDepth:         maxDepth,
		BaseURL:          baseURL,
		Domain:           util.ExtractDomain(baseURL),
	}
}

// Start 开始爬取网页内容
func (c *Crawler) Start() error {
	fmt.Printf("[INFO] 开始爬取: %s\n", c.BaseURL)
	fmt.Printf("[INFO] 最大深度: %d\n", c.MaxDepth)
	fmt.Printf("[INFO] 线程数: %d\n", config.Conf.Thread)

	// 从基础URL开始递归爬取
	c.crawlPage(c.BaseURL, 0)

	fmt.Printf("[INFO] 爬取完成\n")
	fmt.Printf("[INFO] 发现JS文件: %d个\n", len(c.JSFiles))
	fmt.Printf("[INFO] 发现链接: %d个\n", len(c.Links))
	fmt.Printf("[INFO] 发现敏感信息: %d个\n", len(c.SensitiveInfo))

	return nil
}

// CrawlTask 爬取任务
type CrawlTask struct {
	URL   string
	Depth int
}

// worker 工作协程
func (c *Crawler) worker(workChan <-chan CrawlTask, wg *sync.WaitGroup) {
	defer wg.Done()

	for task := range workChan {
		c.crawlPage(task.URL, task.Depth)
		config.IncrementProgress()
	}
}

// crawlPage 爬取单个页面
func (c *Crawler) crawlPage(targetURL string, depth int) {
	// 检查是否已访问
	c.mu.Lock()
	if c.Visited[targetURL] {
		c.mu.Unlock()
		return
	}
	c.Visited[targetURL] = true
	c.mu.Unlock()

	// 检查深度限制
	if depth > c.MaxDepth {
		return
	}

	// 检查域名限制
	if !util.IsSameDomain(targetURL, c.BaseURL) {
		return
	}

	// 检查危险路由（所有模式都过滤）
	if util.IsDangerousRoute(targetURL) {
		c.addSkippedDangerousRoute(targetURL, "危险关键词")
		fmt.Printf("[WARN] 跳过危险路由: %s\n", targetURL)
		return
	}

	fmt.Printf("[INFO] 爬取页面: %s (深度: %d)\n", targetURL, depth)

	// 发送HTTP请求
	resp, err := c.HTTPClient.Get(targetURL)
	if err != nil {
		fmt.Printf("[ERROR] 请求失败: %s - %v\n", targetURL, err)
		return
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[ERROR] 读取响应失败: %s - %v\n", targetURL, err)
		return
	}

	content := string(body)

	// 记录链接信息
	title := c.extractTitle(content)
	// 检查响应内容是否包含权限相关关键词
	if c.containsUnauthorizedKeywords(content) {
		if title == "" {
			title = "需要鉴权"
		} else {
			title = title + " [需要鉴权]"
		}
	}

	c.mu.Lock()
	c.Links = append(c.Links, mode.Link{
		Url:    targetURL,
		Status: fmt.Sprintf("%d", resp.StatusCode),
		Size:   fmt.Sprintf("%d", len(body)),
		Title:  title,
		Source: "", // 页面链接的来源为空，表示是直接访问的
	})
	c.mu.Unlock()

	// 提取JS文件
	c.extractJSFiles(targetURL, content)

	// 提取敏感信息
	c.extractSensitiveInfo(targetURL, content)

	// 提取域名信息
	c.extractDomainInfo(targetURL, content)

	// 提取新链接（如果未达到最大深度）
	if depth < c.MaxDepth {
		newLinks := c.extractLinks(targetURL, content)
		// 将提取的链接添加到Links列表中并设置来源
		c.addExtractedLinks(newLinks, targetURL)
		// 递归爬取新链接
		for _, link := range newLinks {
			c.crawlPage(link, depth+1)
		}
	}
}

// extractTitle 提取页面标题
func (c *Crawler) extractTitle(content string) string {
	re := regexp.MustCompile(`<title[^>]*>([^<]*)</title>`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// extractContentSummary 从页面内容中提取内容摘要
func (c *Crawler) extractContentSummary(content string) string {
	if content == "" {
		return ""
	}

	// 使用配置中的未授权关键词列表
	keywords := config.Conf.UnauthorizedKeywords

	// 查找关键词并提取周围文本
	contentLower := strings.ToLower(content)
	for _, keyword := range keywords {
		keywordLower := strings.ToLower(keyword)
		if idx := strings.Index(contentLower, keywordLower); idx != -1 {
			// 提取关键词周围的文本（前后各10个字符）
			start := idx - 10
			if start < 0 {
				start = 0
			}
			end := idx + len(keyword) + 10
			if end > len(content) {
				end = len(content)
			}
			extract := strings.TrimSpace(content[start:end])
			// 清理HTML标签
			extract = c.cleanHTML(extract)
			if len(extract) > 20 {
				return util.Truncate(extract, 20)
			}
			return extract
		}
	}

	// 如果没有找到关键词，尝试提取页面标题或第一行文本
	if title := c.extractTitle(content); title != "" {
		return util.Truncate(title, 20)
	}

	// 提取第一行有意义的文本
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(c.cleanHTML(line))
		if len(line) > 5 && !strings.HasPrefix(line, "<") {
			return util.Truncate(line, 20)
		}
	}

	return ""
}

// cleanHTML 简单清理HTML标签
func (c *Crawler) cleanHTML(text string) string {
	// 移除HTML标签
	re := regexp.MustCompile(`<[^>]*>`)
	text = re.ReplaceAllString(text, "")
	// 移除多余的空白字符
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

// containsUnauthorizedKeywords 检查内容是否包含权限相关关键词
func (c *Crawler) containsUnauthorizedKeywords(content string) bool {
	contentLower := strings.ToLower(content)
	for _, keyword := range config.Conf.UnauthorizedKeywords {
		if strings.Contains(contentLower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// extractJSFiles 提取JS文件
func (c *Crawler) extractJSFiles(baseURL, content string) {
	for _, pattern := range config.Conf.JsFind {
		matches := util.RegexFindSubmatch(pattern, content)
		for _, match := range matches {
			if len(match) > 1 {
				jsURL := util.NormalizeURL(baseURL, util.TrimQuotes(match[1]))
				if jsURL != "" && !c.isJSFileExists(jsURL) {
					// 过滤不需要的JS文件
					if c.shouldFilterJS(jsURL) {
						continue
					}

					// 获取JS文件内容
					jsFile := c.fetchJSFile(jsURL, baseURL)
					if jsFile.Url != "" {
						c.mu.Lock()
						c.JSFiles = append(c.JSFiles, jsFile)
						c.mu.Unlock()
					}
				}
			}
		}
	}
}

// extractSensitiveInfo 提取敏感信息
func (c *Crawler) extractSensitiveInfo(sourceURL, content string) {
	// 提取手机号
	if patterns, ok := config.Conf.InfoFind["phone"]; ok {
		for _, pattern := range patterns {
			matches := util.RegexFind(pattern, content)
			for _, match := range matches {
				c.addSensitiveInfo("phone", util.TrimQuotes(match), sourceURL)
			}
		}
	}

	// 提取邮箱
	if patterns, ok := config.Conf.InfoFind["email"]; ok {
		for _, pattern := range patterns {
			matches := util.RegexFind(pattern, content)
			for _, match := range matches {
				c.addSensitiveInfo("email", util.TrimQuotes(match), sourceURL)
			}
		}
	}

	// 提取身份证
	if patterns, ok := config.Conf.InfoFind["idcard"]; ok {
		for _, pattern := range patterns {
			matches := util.RegexFind(pattern, content)
			for _, match := range matches {
				c.addSensitiveInfo("idcard", util.TrimQuotes(match), sourceURL)
			}
		}
	}

	// 提取JWT
	if patterns, ok := config.Conf.InfoFind["jwt"]; ok {
		for _, pattern := range patterns {
			matches := util.RegexFind(pattern, content)
			for _, match := range matches {
				c.addSensitiveInfo("jwt", util.TrimQuotes(match), sourceURL)
			}
		}
	}

	// 提取密钥
	if patterns, ok := config.Conf.InfoFind["key"]; ok {
		for _, pattern := range patterns {
			matches := util.RegexFindSubmatch(pattern, content)
			for _, match := range matches {
				if len(match) > 2 {
					c.addSensitiveInfo("key", fmt.Sprintf("%s=%s", match[1], match[2]), sourceURL)
				}
			}
		}
	}

	// 提取密码
	if patterns, ok := config.Conf.InfoFind["password"]; ok {
		for _, pattern := range patterns {
			matches := util.RegexFindSubmatch(pattern, content)
			for _, match := range matches {
				if len(match) > 2 {
					c.addSensitiveInfo("password", fmt.Sprintf("%s=%s", match[1], match[2]), sourceURL)
				}
			}
		}
	}

	// 提取用户名
	if patterns, ok := config.Conf.InfoFind["name"]; ok {
		for _, pattern := range patterns {
			matches := util.RegexFindSubmatch(pattern, content)
			for _, match := range matches {
				if len(match) > 2 {
					c.addSensitiveInfo("name", fmt.Sprintf("%s=%s", match[1], match[2]), sourceURL)
				}
			}
		}
	}

	// 提取其他敏感信息
	if patterns, ok := config.Conf.InfoFind["other"]; ok {
		for _, pattern := range patterns {
			matches := util.RegexFindSubmatch(pattern, content)
			for _, match := range matches {
				if len(match) > 2 {
					c.addSensitiveInfo("other", fmt.Sprintf("%s=%s", match[1], match[2]), sourceURL)
				}
			}
		}
	}
}

// extractLinks 提取链接
func (c *Crawler) extractLinks(baseURL, content string) []string {
	var links []string

	for _, pattern := range config.Conf.UrlFind {
		matches := util.RegexFindSubmatch(pattern, content)
		for _, match := range matches {
			if len(match) > 1 {
				link := util.NormalizeURL(baseURL, util.TrimQuotes(match[1]))
				if link != "" && util.IsValidURL(link) {
					// 过滤不需要的链接
					if !c.shouldFilterURL(link) {
						links = append(links, link)
					}
				}
			}
		}
	}

	return util.RemoveDuplicates(links)
}

// fetchJSFile 获取JS文件
func (c *Crawler) fetchJSFile(jsURL, sourceURL string) mode.JSFile {
	resp, err := c.HTTPClient.Get(jsURL)
	if err != nil {
		fmt.Printf("[ERROR] 获取JS文件失败: %s - %v\n", jsURL, err)
		return mode.JSFile{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[ERROR] 读取JS文件失败: %s - %v\n", jsURL, err)
		return mode.JSFile{}
	}

	content := string(body)
	jsFile := mode.JSFile{
		Url:       jsURL,
		Status:    fmt.Sprintf("%d", resp.StatusCode),
		Size:      fmt.Sprintf("%d", len(body)),
		Source:    sourceURL,
		APIs:      make([]string, 0),
		Sensitive: make([]mode.Info, 0),
		IsTarget:  false,
	}

	// 提取API接口
	jsFile.APIs = c.extractAPIsFromJS(content)

	// 将提取的API作为Link添加到Links列表中
	c.addAPIsAsLinks(jsFile.APIs, jsURL)

	// 提取敏感信息
	c.extractSensitiveInfoFromJS(jsURL, content)

	return jsFile
}

// extractAPIsFromJS 从JS文件中提取API接口
func (c *Crawler) extractAPIsFromJS(content string) []string {
	var apis []string

	// API路径模式
	for _, pattern := range config.APIPatterns {
		matches := util.RegexFind(pattern, content)
		for _, match := range matches {
			api := util.TrimQuotes(match)
			if api != "" && len(api) > 1 && api != "/" {
				// 过滤掉根路径和太短的路径
				apis = append(apis, api)
			}
		}
	}

	return util.RemoveDuplicates(apis)
}

// extractSensitiveInfoFromJS 从JS文件中提取敏感信息
func (c *Crawler) extractSensitiveInfoFromJS(jsURL, content string) {
	c.extractSensitiveInfo(jsURL, content)
}

// addAPIsAsLinks 将API作为Link添加到Links列表中
func (c *Crawler) addAPIsAsLinks(apis []string, jsURL string) {
	for _, api := range apis {
		// 构建完整的API URL
		apiURL := util.NormalizeURL(c.BaseURL, api)
		if apiURL != "" {
			// 检查是否为危险路由（在获取锁之前检查）
			if util.IsDangerousRoute(apiURL) {
				c.addSkippedDangerousRoute(apiURL, "危险关键词")
				continue // 跳过危险路由
			}

			c.mu.Lock()
			// 检查是否已存在
			exists := false
			for _, link := range c.Links {
				if link.Url == apiURL {
					exists = true
					break
				}
			}

			if !exists {
				// 尝试获取API的状态码和基本信息
				c.mu.Unlock() // 在进行HTTP请求前释放锁
				status, size, title, content := c.getLinkInfo(apiURL)
				// 提取页面内容摘要
				contentSummary := c.extractContentSummary(content)
				c.mu.Lock() // 重新获取锁以添加到Links
				c.Links = append(c.Links, mode.Link{
					Url:     apiURL,
					Status:  status,
					Size:    size,
					Title:   title,
					Content: contentSummary,
					Source:  jsURL, // 设置来源为JS文件URL
				})
			}
			c.mu.Unlock()
		}
	}
}

// addExtractedLinks 将提取的链接添加到Links列表中并设置来源
func (c *Crawler) addExtractedLinks(links []string, sourceURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, link := range links {
		// 检查是否已存在
		exists := false
		for _, existingLink := range c.Links {
			if existingLink.Url == link {
				exists = true
				break
			}
		}

		if !exists {
			// 尝试获取链接的状态码
			status, size, title, content := c.getLinkInfo(link)
			// 提取页面内容摘要
			contentSummary := c.extractContentSummary(content)
			c.Links = append(c.Links, mode.Link{
				Url:     link,
				Status:  status,
				Size:    size,
				Title:   title,
				Content: contentSummary,
				Source:  sourceURL, // 设置来源为发现该链接的页面URL
			})
		}
	}
}

// getLinkInfo 获取链接的基本信息（状态码、大小、标题）
func (c *Crawler) getLinkInfo(url string) (status, size, title, content string) {
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return "", "", "", ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("%d", resp.StatusCode), "", "", ""
	}

	content = string(body)
	title = c.extractTitle(content)
	// 检查响应内容是否包含权限相关关键词
	if c.containsUnauthorizedKeywords(content) {
		if title == "" {
			title = "需要鉴权"
		} else {
			title = title + " [需要鉴权]"
		}
	}
	return fmt.Sprintf("%d", resp.StatusCode), fmt.Sprintf("%d", len(body)), title, content
}

// extractDomainInfo 提取域名信息
func (c *Crawler) extractDomainInfo(sourceURL, content string) {
	// 首次调用时添加目标域名本身
	if len(c.DomainInfo) == 0 {
		targetDomain := util.ExtractDomain(c.BaseURL)
		if targetDomain != "" {
			c.mu.Lock()
			c.DomainInfo = append(c.DomainInfo, mode.DomainInfo{
				Domain:    targetDomain,
				IP:        "",
				Type:      "internal",
				CloudType: "",
				Source:    c.BaseURL,
			})
			c.mu.Unlock()
		}
	}

	// 提取域名
	for _, pattern := range config.Conf.DomainFind {
		matches := util.RegexFindSubmatch(pattern, content)
		for _, match := range matches {
			if len(match) > 1 {
				domain := strings.ToLower(util.TrimQuotes(match[1]))
				if domain != "" && !c.isDomainExists(domain) {
					domainType := c.getDomainType(domain)
					cloudType := c.getCloudType(domain)

					c.mu.Lock()
					c.DomainInfo = append(c.DomainInfo, mode.DomainInfo{
						Domain:    domain,
						IP:        "", // 可以后续添加IP解析
						Type:      domainType,
						CloudType: cloudType,
						Source:    sourceURL,
					})
					c.mu.Unlock()
				}
			}
		}
	}

	// 提取IP地址
	for _, pattern := range config.Conf.IPFind {
		matches := util.RegexFind(pattern, content)
		for _, match := range matches {
			ip := util.TrimQuotes(match)
			if ip != "" && !c.isIPExists(ip) {
				ipType := c.getIPType(ip)

				c.mu.Lock()
				c.DomainInfo = append(c.DomainInfo, mode.DomainInfo{
					Domain:    ip,
					IP:        ip,
					Type:      ipType,
					CloudType: "",
					Source:    sourceURL,
				})
				c.mu.Unlock()
			}
		}
	}
}

// isDomainExists 检查域名是否已存在
func (c *Crawler) isDomainExists(domain string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, info := range c.DomainInfo {
		if info.Domain == domain {
			return true
		}
	}
	return false
}

// isIPExists 检查IP是否已存在
func (c *Crawler) isIPExists(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, info := range c.DomainInfo {
		if info.IP == ip {
			return true
		}
	}
	return false
}

// getDomainType 获取域名类型
func (c *Crawler) getDomainType(domain string) string {
	// 检查是否为目标域名
	if strings.Contains(domain, c.Domain) {
		return "internal"
	}

	// 检查是否为云服务域名
	for _, pattern := range config.Conf.CloudDomains {
		matched, err := regexp.MatchString(pattern, domain)
		if err == nil && matched {
			return "cloud"
		}
	}

	return "external"
}

// getCloudType 获取云服务类型
func (c *Crawler) getCloudType(domain string) string {
	if strings.Contains(domain, "amazonaws.com") {
		return "AWS"
	}
	if strings.Contains(domain, "aliyuncs.com") || strings.Contains(domain, "aliyun.com") {
		return "阿里云"
	}
	if strings.Contains(domain, "myqcloud.com") || strings.Contains(domain, "tencentcloudapi.com") || strings.Contains(domain, "qcloud.com") {
		return "腾讯云"
	}
	if strings.Contains(domain, "baidubce.com") || strings.Contains(domain, "bcebos.com") || strings.Contains(domain, "bcehost.com") {
		return "百度云"
	}
	if strings.Contains(domain, "hwclouds.com") || strings.Contains(domain, "huaweicloud.com") || strings.Contains(domain, "myhwclouds.com") {
		return "华为云"
	}
	if strings.Contains(domain, "azure.com") || strings.Contains(domain, "azurewebsites.net") || strings.Contains(domain, "cloudapp.azure.com") {
		return "Azure"
	}
	if strings.Contains(domain, "googleapis.com") || strings.Contains(domain, "googleusercontent.com") || strings.Contains(domain, "appspot.com") || strings.Contains(domain, "cloudfunctions.net") {
		return "Google Cloud"
	}
	return ""
}

// getIPType 获取IP类型
func (c *Crawler) getIPType(ip string) string {
	// 简单的内网IP判断
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
		return "internal"
	}
	return "external"
}

// addSensitiveInfo 添加敏感信息
func (c *Crawler) addSensitiveInfo(infoType, value, source string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查敏感信息是否已存在
	for i := range c.SensitiveInfo {
		if c.SensitiveInfo[i].Source == source {
			// 更新现有信息
			switch infoType {
			case "phone":
				for _, phone := range c.SensitiveInfo[i].Phone {
					if phone == value {
						return
					}
				}
				c.SensitiveInfo[i].Phone = append(c.SensitiveInfo[i].Phone, value)
			case "email":
				for _, email := range c.SensitiveInfo[i].Email {
					if email == value {
						return
					}
				}
				c.SensitiveInfo[i].Email = append(c.SensitiveInfo[i].Email, value)
			case "idcard":
				for _, idcard := range c.SensitiveInfo[i].IDcard {
					if idcard == value {
						return
					}
				}
				c.SensitiveInfo[i].IDcard = append(c.SensitiveInfo[i].IDcard, value)
			case "jwt":
				for _, jwt := range c.SensitiveInfo[i].JWT {
					if jwt == value {
						return
					}
				}
				c.SensitiveInfo[i].JWT = append(c.SensitiveInfo[i].JWT, value)
			case "key":
				for _, key := range c.SensitiveInfo[i].Key {
					if key == value {
						return
					}
				}
				c.SensitiveInfo[i].Key = append(c.SensitiveInfo[i].Key, value)
			case "password":
				for _, password := range c.SensitiveInfo[i].Password {
					if password == value {
						return
					}
				}
				c.SensitiveInfo[i].Password = append(c.SensitiveInfo[i].Password, value)
			case "name":
				for _, name := range c.SensitiveInfo[i].Name {
					if name == value {
						return
					}
				}
				c.SensitiveInfo[i].Name = append(c.SensitiveInfo[i].Name, value)
			case "other":
				for _, other := range c.SensitiveInfo[i].Other {
					if other == value {
						return
					}
				}
				c.SensitiveInfo[i].Other = append(c.SensitiveInfo[i].Other, value)
			}
			return
		}
	}

	// 创建新的敏感信息
	newInfo := mode.Info{
		Source: source,
	}
	switch infoType {
	case "phone":
		newInfo.Phone = []string{value}
	case "email":
		newInfo.Email = []string{value}
	case "idcard":
		newInfo.IDcard = []string{value}
	case "jwt":
		newInfo.JWT = []string{value}
	case "key":
		newInfo.Key = []string{value}
	case "password":
		newInfo.Password = []string{value}
	case "name":
		newInfo.Name = []string{value}
	case "other":
		newInfo.Other = []string{value}
	}
	c.SensitiveInfo = append(c.SensitiveInfo, newInfo)
}

// isJSFileExists 检查JS文件是否已存在
func (c *Crawler) isJSFileExists(jsURL string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, jsFile := range c.JSFiles {
		if jsFile.Url == jsURL {
			return true
		}
	}
	return false
}

// shouldFilterJS 判断是否应该过滤JS文件
func (c *Crawler) shouldFilterJS(jsURL string) bool {
	for _, pattern := range config.Conf.JsFiler {
		matched, err := regexp.MatchString(pattern, jsURL)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// shouldFilterURL 判断是否应该过滤URL
func (c *Crawler) shouldFilterURL(targetURL string) bool {
	// 检查URL过滤规则
	for _, pattern := range config.Conf.UrlFiler {
		matched, err := regexp.MatchString(pattern, targetURL)
		if err == nil && matched {
			return true
		}
	}

	// 检查危险路由（所有模式都过滤）
	if util.IsDangerousRoute(targetURL) {
		c.addSkippedDangerousRoute(targetURL, "危险关键词")
		return true
	}

	return false
}

// addSkippedDangerousRoute 记录跳过的危险路由
func (c *Crawler) addSkippedDangerousRoute(url, keyword string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 添加到链接列表中，标记为跳过的危险路由
	skippedLink := mode.Link{
		Url:    url,
		Status: "SKIPPED",
		Size:   "0",
		Title:  fmt.Sprintf("危险路由已跳过 (包含关键词: %s)", keyword),
		Source: "危险路由过滤",
	}
	c.Links = append(c.Links, skippedLink)
}

// GetResults 获取爬取结果
func (c *Crawler) GetResults() ([]mode.JSFile, []mode.Link, []mode.Info, []mode.FuzzResult, []mode.DomainInfo) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.JSFiles, c.Links, c.SensitiveInfo, c.FuzzResults, c.DomainInfo
}

// AddFuzzResult 添加模糊测试结果
func (c *Crawler) AddFuzzResult(result mode.FuzzResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.FuzzResults = append(c.FuzzResults, result)
}
