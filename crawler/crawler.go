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
	JSFileCheck      map[string]struct{}    // JS文件查重
	Links            []mode.Link            // 发现的链接列表
	LinkCheck        map[string]struct{}    // Link查重
	SensitiveInfo    []mode.Info            // 提取的敏感信息
	sourceInfoMap    map[string]int         // 判断是否存储过该源地址的敏感信息
	SensitiveCheck   map[string]struct{}    // 敏感信息查重
	FuzzResults      []mode.FuzzResult      // 模糊测试结果
	DomainInfo       []mode.DomainInfo      // 域名信息
	DomainCheck      map[string]struct{}    // 域名查重
	IpCheck          map[string]struct{}    // IP查重
	ParamFuzzResults []mode.ParamFuzzResult // 参数模糊测试结果
	mu               sync.RWMutex           // 读写锁，保证并发安全
	Depth            int                    // 当前爬取深度
	MaxDepth         int                    // 最大爬取深度
	BaseURL          string                 // 基础URL
	Domain           string                 // 目标域名
	LinkConcurrency  int                    // 链接爬取并发数
	JSConcurrency    int                    // JS文件获取并发数
}

// NewCrawler 创建新的爬虫实例
func NewCrawler(baseURL string, maxDepth int, threadCount int) *Crawler {
	// 根据线程数设置并发数，确保合理的并发控制
	linkConcurrency := threadCount / 3
	if linkConcurrency < 1 {
		linkConcurrency = 1
	}
	if linkConcurrency > 10 {
		linkConcurrency = 10
	}
	
	jsConcurrency := threadCount / 2
	if jsConcurrency < 1 {
		jsConcurrency = 1
	}
	if jsConcurrency > 20 {
		jsConcurrency = 20
	}
	

	return &Crawler{
		HTTPClient:       util.NewHTTPClient(),
		Visited:          make(map[string]bool),
		JSFiles:          make([]mode.JSFile, 0),
		JSFileCheck:      make(map[string]struct{}),
		Links:            make([]mode.Link, 0),
		LinkCheck:        make(map[string]struct{}),
		SensitiveInfo:    make([]mode.Info, 0),
		sourceInfoMap:    make(map[string]int),
		SensitiveCheck:   make(map[string]struct{}),
		FuzzResults:      make([]mode.FuzzResult, 0),
		DomainInfo:       make([]mode.DomainInfo, 0),
		DomainCheck:      make(map[string]struct{}),
		IpCheck:          make(map[string]struct{}),
		ParamFuzzResults: make([]mode.ParamFuzzResult, 0),
		Depth:            0,
		MaxDepth:         maxDepth,
		BaseURL:          baseURL,
		Domain:           util.ExtractDomain(baseURL),
		LinkConcurrency:  linkConcurrency,
		JSConcurrency:    jsConcurrency,
	}
}

// Start 开始爬取网页内容
func (c *Crawler) Start() error {
	fmt.Printf("[INFO] 开始爬取: %s\n", c.BaseURL)
	fmt.Printf("[INFO] 最大深度: %d\n", c.MaxDepth)
	fmt.Printf("[INFO] 线程数: %d\n", config.Conf.Thread)

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
	c.mu.Lock()
	if c.Visited[targetURL] {
		c.mu.Unlock()
		return
	}
	c.Visited[targetURL] = true
	c.mu.Unlock()

	if depth > c.MaxDepth {
		return
	}

	if !util.IsSameDomain(targetURL, c.BaseURL) {
		return
	}

	if util.IsDangerousRoute(targetURL) {
		c.addSkippedDangerousRoute(targetURL, "危险关键词")
		fmt.Printf("[WARN] 跳过危险路由: %s\n", targetURL)
		return
	}

	fmt.Printf("[INFO] 爬取页面: %s (深度: %d)\n", targetURL, depth)

	resp, err := c.HTTPClient.Get(targetURL)
	if err != nil {
		fmt.Printf("[ERROR] 请求失败: %s - %v\n", targetURL, err)
		return
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[ERROR] 读取响应失败: %s - %v\n", targetURL, err)
		return
	}

	content := string(body)

	title := c.extractTitle(content)
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
		Source: "",
	})
	c.mu.Unlock()

	c.extractJSFiles(targetURL, content)
	c.extractSensitiveInfo(targetURL, content)
	c.extractDomainInfo(targetURL, content)

	if depth < c.MaxDepth {
		newLinks := c.extractLinks(targetURL, content)
		c.addExtractedLinks(newLinks, targetURL)
		c.crawlLinksParallel(newLinks, depth+1)
	}
}

// crawlLinksParallel 并发爬取链接
func (c *Crawler) crawlLinksParallel(links []string, depth int) {
	if len(links) == 0 {
		return
	}

	maxConcurrent := c.LinkConcurrency
	if len(links) < maxConcurrent {
		maxConcurrent = len(links)
	}

	linkChan := make(chan string, len(links))
	var wg sync.WaitGroup

	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for link := range linkChan {
				c.crawlPage(link, depth)
			}
		}()
	}

	for _, link := range links {
		linkChan <- link
	}

	close(linkChan)
	wg.Wait()
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

// extractContentSummary 从页面内容中提取鉴权内容摘要
func (c *Crawler) extractContentSummary(content string) string {
	if content == "" {
		return ""
	}
	keywords := config.Conf.UnauthorizedKeywords
	contentLower := strings.ToLower(content)
	for _, keyword := range keywords {
		keywordLower := strings.ToLower(keyword)
		if idx := strings.Index(contentLower, keywordLower); idx != -1 {
			start := idx - 10
			if start < 0 {
				start = 0
			}
			end := idx + len(keyword) + 10
			if end > len(content) {
				end = len(content)
			}
			extract := strings.TrimSpace(content[start:end])
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
	re := regexp.MustCompile(`<[^>]*>`)
	text = re.ReplaceAllString(text, "")
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
	var jsURLs []string
	
	// 收集所有JS URL
	for _, pattern := range config.Conf.JsFind {
		matches := util.RegexFindSubmatch(pattern, content)
		for _, match := range matches {
			if len(match) > 1 {
				jsURL := util.NormalizeURL(baseURL, util.TrimQuotes(match[1]))
				if jsURL != "" && !c.isJSFileExists(jsURL) {
					if c.shouldFilterJS(jsURL) {
						continue
					}
					jsURLs = append(jsURLs, jsURL)
				}
			}
		}
	}
	
	if len(jsURLs) == 0 {
		return
	}
	
	c.fetchJSFilesParallel(jsURLs, baseURL)
}

// fetchJSFilesParallel 并发获取JS文件
func (c *Crawler) fetchJSFilesParallel(jsURLs []string, baseURL string) {
	maxConcurrent := c.JSConcurrency
	if len(jsURLs) < maxConcurrent {
		maxConcurrent = len(jsURLs)
	}

	jsURLChan := make(chan string, len(jsURLs))
	var wg sync.WaitGroup

	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jsURL := range jsURLChan {
				jsFile := c.fetchJSFile(jsURL, baseURL)
				if jsFile.Url != "" {
					c.mu.Lock()
					c.JSFiles = append(c.JSFiles, jsFile)
					c.mu.Unlock()
				}
			}
		}()
	}

	for _, jsURL := range jsURLs {
		jsURLChan <- jsURL
	}

	close(jsURLChan)
	wg.Wait()
}

// extractSensitiveInfo 提取敏感信息
func (c *Crawler) extractSensitiveInfo(sourceURL, content string) {
	// 定义信息类型和对应的处理方式
	typeMap := map[string]bool{
		"phone":    false,
		"email":    false,
		"idcard":   false,
		"jwt":      false,
		"key":      true,
		"password": true,
		"name":     true,
		"other":    true,
	}
	
	c.extractSensitiveInfoParallel(sourceURL, content, typeMap)
}

// extractSensitiveInfoParallel 并发提取敏感信息
func (c *Crawler) extractSensitiveInfoParallel(sourceURL, content string, typeMap map[string]bool) {
	var wg sync.WaitGroup
	
	for infoType, isCompound := range typeMap {
		if patterns, ok := config.Conf.InfoFind[infoType]; ok {
			wg.Add(1)
			go func(iType string, iCompound bool, iPatterns []string) {
				defer wg.Done()
				for _, pattern := range iPatterns {
					if iCompound {
						matches := util.RegexFindSubmatch(pattern, content)
						for _, match := range matches {
							if len(match) > 2 {
								c.addSensitiveInfo(iType, fmt.Sprintf("%s=%s", match[1], match[2]), sourceURL)
							}
						}
					} else {
						matches := util.RegexFind(pattern, content)
						for _, match := range matches {
							c.addSensitiveInfo(iType, util.TrimQuotes(match), sourceURL)
						}
					}
				}
			}(infoType, isCompound, patterns)
		}
	}
	
	wg.Wait()
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
	jsFile.APIs = c.extractAPIsFromJS(content)
	c.addAPIsAsLinks(jsFile.APIs, jsURL)
	c.extractSensitiveInfoFromJS(jsURL, content)

	return jsFile
}

// extractAPIsFromJS 从JS文件中提取API接口
func (c *Crawler) extractAPIsFromJS(content string) []string {
	var apis []string
	for _, pattern := range config.APIPatterns {
		matches := util.RegexFind(pattern, content)
		for _, match := range matches {
			api := util.TrimQuotes(match)
			if api != "" && len(api) > 1 && api != "/" {
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
		apiURL := util.NormalizeURL(c.BaseURL, api)
		if apiURL != "" && !c.isLinkExists(apiURL) {
			if util.IsDangerousRoute(apiURL) {
				c.addSkippedDangerousRoute(apiURL, "危险关键词")
				continue
			}

			status, size, title, content := c.getLinkInfo(apiURL)
			contentSummary := c.extractContentSummary(content)
			c.mu.Lock()
			c.Links = append(c.Links, mode.Link{
				Url:     apiURL,
				Status:  status,
				Size:    size,
				Title:   title,
				Content: contentSummary,
				Source:  jsURL,
			})
			c.mu.Unlock()
		}
	}

}

// addExtractedLinks 将提取的链接添加到Links列表中并设置来源
func (c *Crawler) addExtractedLinks(links []string, sourceURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, link := range links {
		exists := false
		for _, existingLink := range c.Links {
			if existingLink.Url == link {
				exists = true
				break
			}
		}

		if !exists {
			status, size, title, content := c.getLinkInfo(link)
			contentSummary := c.extractContentSummary(content)
			c.Links = append(c.Links, mode.Link{
				Url:     link,
				Status:  status,
				Size:    size,
				Title:   title,
				Content: contentSummary,
				Source:  sourceURL,
			})
		}
	}
}

// getLinkInfo 获取链接的基本信息（状态码、大小、标题、内容）
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
			c.DomainCheck[targetDomain] = struct{}{}
			c.mu.Unlock()
		}
	}

	var newDomains []mode.DomainInfo

	// 提取域名
	for _, pattern := range config.Conf.DomainFind {
		matches := util.RegexFindSubmatch(pattern, content)
		for _, match := range matches {
			if len(match) > 1 {
				domain := strings.ToLower(util.TrimQuotes(match[1]))
				if domain == "" {
					continue
				}
				c.mu.RLock()
				_, exists := c.DomainCheck[domain]
				c.mu.RUnlock()

				if !exists {
					domainType := c.getDomainType(domain)
					cloudType := c.getCloudType(domain)

					newDomains = append(newDomains, mode.DomainInfo{
						Domain:    domain,
						IP:        "",
						Type:      domainType,
						CloudType: cloudType,
						Source:    sourceURL,
					})
				}
			}
		}
	}

	// 提取IP地址
	for _, pattern := range config.Conf.IPFind {
		matches := util.RegexFind(pattern, content)
		for _, match := range matches {
			ip := util.TrimQuotes(match)
			if ip == "" {
				continue
			}
			c.mu.RLock()
			_, exists := c.IpCheck[ip]
			c.mu.RUnlock()

			if !exists {
				ipType := c.getIPType(ip)

				newDomains = append(newDomains, mode.DomainInfo{
					Domain:    ip,
					IP:        ip,
					Type:      ipType,
					CloudType: "",
					Source:    sourceURL,
				})
			}
		}
	}

	// 一次性添加所有新域名，减少锁的使用次数
	if len(newDomains) > 0 {
		c.mu.Lock()
		for _, domain := range newDomains {
			// 再次检查，避免在获取锁期间其他goroutine已添加相同域名
			if domain.IP != "" {
				if _, exists := c.IpCheck[domain.IP]; !exists {
					c.DomainInfo = append(c.DomainInfo, domain)
					c.IpCheck[domain.IP] = struct{}{}
				}
			} else {
				if _, exists := c.DomainCheck[domain.Domain]; !exists {
					c.DomainInfo = append(c.DomainInfo, domain)
					c.DomainCheck[domain.Domain] = struct{}{}
				}
			}
		}
		c.mu.Unlock()
	}
}

// isLinkExists 检查链接是否已存在
func (c *Crawler) isLinkExists(link string) bool {
	c.mu.RLock()
	if _, exists := c.LinkCheck[link]; exists {
		c.mu.RUnlock()
		return true
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.LinkCheck[link]; exists {
		return true
	}
	c.LinkCheck[link] = struct{}{}
	return false
}

// isDomainExists 检查域名是否已存在
func (c *Crawler) isDomainExists(domain string) bool {
	c.mu.RLock()
	if _, exists := c.DomainCheck[domain]; exists {
		c.mu.RUnlock()
		return true
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.DomainCheck[domain]; exists {
		return true
	}
	c.DomainCheck[domain] = struct{}{}
	return false
}

// isIPExists 检查IP是否已存在
func (c *Crawler) isIPExists(ip string) bool {
	c.mu.RLock()
	if _, exists := c.IpCheck[ip]; exists {
		c.mu.RUnlock()
		return true
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.IpCheck[ip]; exists {
		return true
	}
	c.IpCheck[ip] = struct{}{}
	return false
}

// getDomainType 获取域名类型
func (c *Crawler) getDomainType(domain string) string {
	if strings.Contains(domain, c.Domain) {
		return "internal"
	}
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

	key := source + ":" + infoType + ":" + value
	if _, exists := c.SensitiveCheck[key]; exists {
		return
	}
	c.SensitiveCheck[key] = struct{}{}

	getFieldByType := func(info *mode.Info, typ string) *[]string {
		switch typ {
		case "phone":
			return &info.Phone
		case "email":
			return &info.Email
		case "idcard":
			return &info.IDcard
		case "jwt":
			return &info.JWT
		case "key":
			return &info.Key
		case "password":
			return &info.Password
		case "name":
			return &info.Name
		case "other":
			return &info.Other
		default:
			return nil
		}
	}

	if idx, exists := c.sourceInfoMap[source]; exists {
		field := getFieldByType(&c.SensitiveInfo[idx], infoType)
		if field == nil {
			return
		}
		*field = append(*field, value)
		return
	}
	newInfo := mode.Info{
		Source: source,
	}
	field := getFieldByType(&newInfo, infoType)
	if field == nil {
		return
	}
	*field = []string{value}
	c.SensitiveInfo = append(c.SensitiveInfo, newInfo)
	c.sourceInfoMap[source] = len(c.SensitiveInfo) - 1
}

// isJSFileExists 检查JS文件是否已存在
func (c *Crawler) isJSFileExists(jsURL string) bool {
	c.mu.RLock()
	if _, exists := c.JSFileCheck[jsURL]; exists {
		c.mu.RUnlock()
		return true
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.JSFileCheck[jsURL]; exists {
		return true
	}
	c.JSFileCheck[jsURL] = struct{}{}
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
	for _, pattern := range config.Conf.UrlFiler {
		matched, err := regexp.MatchString(pattern, targetURL)
		if err == nil && matched {
			return true
		}
	}
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
