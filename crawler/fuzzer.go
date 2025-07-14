package crawler

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Nbccccc/FinderFuzz/config"
	"github.com/Nbccccc/FinderFuzz/mode"
	"github.com/Nbccccc/FinderFuzz/util"
)

// Fuzzer 模糊测试器
type Fuzzer struct {
	HTTPClient *util.HTTPClient // HTTP客户端
	BaseURL    string           // 基础URL
	Crawler    *Crawler         // 爬虫实例
	BaseDir    string           // 基础目录
}



// NewFuzzer 创建新的模糊测试器
func NewFuzzer(baseURL string, crawler *Crawler) *Fuzzer {
	return &Fuzzer{
		HTTPClient: util.NewHTTPClient(),
		BaseURL:    baseURL,
		Crawler:    crawler,
	}
}

// SetBaseDir 设置基础目录
func (f *Fuzzer) SetBaseDir(baseDir string) {
	f.BaseDir = baseDir
}

// extractTitle 提取页面标题
func (f *Fuzzer) extractTitle(content string) string {
	if len(content) > 1000 {
		content = content[:1000] // 只检查前1000个字符
	}

	matches := util.RegexFindSubmatch(`<title[^>]*>([^<]*)</title>`, content)
	if len(matches) > 1 && len(matches[1]) > 0 {
		return strings.TrimSpace(matches[1][0])
	}
	return ""
}

// containsSensitiveInfo 检查是否包含敏感信息
func (f *Fuzzer) containsSensitiveInfo(content string) bool {
	if len(content) > 5000 {
		content = content[:5000] // 只检查前5000个字符
	}

	// 检查常见的敏感信息模式
	for _, pattern := range config.SensitivePatterns {
		matched := util.RegexFind("(?i)"+pattern, content)
		if len(matched) > 0 {
			return true
		}
	}

	return false
}

// isInterestingResponse 判断是否为有趣的响应
func (f *Fuzzer) isInterestingResponse(statusCode int, content string) bool {
	// 成功状态码
	if util.IsSuccessStatusCode(statusCode) {
		return true
	}

	// 重定向状态码
	if util.IsRedirectStatusCode(statusCode) {
		return true
	}

	// 特定的错误状态码
	for _, code := range config.InterestingStatusCodes {
		if statusCode == code {
			return true
		}
	}

	// 响应内容大小异常
	if len(content) > 10000 || (len(content) > 0 && len(content) < 100) {
		return true
	}

	return false
}

// StartFuzzing 开始模糊测试
func (f *Fuzzer) StartFuzzing() error {
	fmt.Printf("[INFO] 开始模糊测试\n")

	// 获取404链接进行目录fuzz
	fuzzURLs := f.generateDirectoryFuzzURLs()
	fmt.Printf("[INFO] 发现API接口: %d个\n", len(fuzzURLs))

	if len(fuzzURLs) == 0 {
		fmt.Printf("[WARN] 未发现可fuzz的404链接，跳过模糊测试\n")
		return nil
	}

	// 创建工作池
	workChan := make(chan string, len(fuzzURLs))
	var wg sync.WaitGroup

	// 启动工作协程
	for i := 0; i < config.Conf.Thread; i++ {
		wg.Add(1)
		go f.directoryFuzzWorker(workChan, &wg)
	}

	// 添加模糊测试任务
	for _, fuzzURL := range fuzzURLs {
		workChan <- fuzzURL
	}

	close(workChan)

	// 等待所有任务完成
	wg.Wait()

	fmt.Printf("[INFO] 模糊测试完成\n")
	fmt.Printf("[INFO] 测试结果: %d个\n", len(f.Crawler.FuzzResults))

	return nil
}

// FuzzTask 模糊测试任务
type FuzzTask struct {
	URL      string
	Method   string
	Source   string
	Original string
	Payload  string
	FuzzType string
}

// APIInfo API信息
type APIInfo struct {
	Path   string
	Source string
}

// TestURL 测试URL
type TestURL struct {
	URL      string
	Method   string
	Payload  string
	FuzzType string
}

// directoryFuzzWorker 目录模糊测试工作协程
func (f *Fuzzer) directoryFuzzWorker(workChan <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for fuzzURL := range workChan {
		f.testDirectoryURL(fuzzURL)
		config.IncrementFuzzNum()
		time.Sleep(time.Duration(config.Conf.Timeout) * time.Millisecond)
	}
}

// generateDirectoryFuzzURLs 生成目录fuzz的URL列表
func (f *Fuzzer) generateDirectoryFuzzURLs() []string {
	// 如果指定了BaseDir，使用BaseDir模式
	if f.BaseDir != "" {
		return f.generateBaseDirFuzz()
	}

	// 获取所有404链接
	var links404 []string
	for _, link := range f.Crawler.Links {
		if link.Status == "404" {
			// 跳过危险路由
			if util.IsDangerousRoute(link.Url) {
				fmt.Printf("[WARN] 跳过危险路由模糊测试: %s\n", link.Url)
				continue
			}
			links404 = append(links404, link.Url)
		}
	}

	if len(links404) == 0 {
		return []string{}
	}

	// 根据fuzz模式生成URL
	var fuzzURLs []string
	fuzzMode := f.getFuzzMode()

	switch fuzzMode {
	case 1: // decreasing - 目录递减fuzz
		fuzzURLs = f.generateDecreasingFuzz(links404)
	case 2: // 2combination - 2级目录组合fuzz
		fuzzURLs = f.generateCombinationFuzz(links404, 2)
	case 3: // 3combination - 3级目录组合fuzz
		fuzzURLs = f.generateCombinationFuzz(links404, 3)
	default:
		fuzzURLs = f.generateDecreasingFuzz(links404)
	}

	return util.RemoveDuplicates(fuzzURLs)
}

// getFuzzMode 获取fuzz模式
func (f *Fuzzer) getFuzzMode() int {
	// 从命令行参数获取fuzz模式，默认为1
	fuzzNum := config.GetFuzzNum()
	if fuzzNum > 0 {
		return fuzzNum
	}
	return 1
}

// generateDecreasingFuzz 生成目录递减fuzz URL
func (f *Fuzzer) generateDecreasingFuzz(links404 []string) []string {
	var fuzzURLs []string
	var baseHost string

	if len(links404) > 0 {
		// 提取基础主机
		if matches := util.RegexFindSubmatch(`(https?://[^/]+)`, links404[0]); len(matches) > 0 && len(matches[0]) > 1 {
			baseHost = matches[0][1]
		}
	}

	for _, link := range links404 {
		// 提取路径部分
		if matches := util.RegexFindSubmatch(`https?://[^/]+(.*)`, link); len(matches) > 0 && len(matches[0]) > 1 {
			path := matches[0][1]
			if path == "" {
				continue
			}

			// 目录递减fuzz
			currentPath := path
			fileName := ""

			// 如果不是以/结尾，提取文件名
			if !strings.HasSuffix(path, "/") {
				if matches := util.RegexFindSubmatch(`(.*/)?([^/]+)$`, path); len(matches) > 0 && len(matches[0]) > 2 {
					currentPath = matches[0][1]
					fileName = matches[0][2]
				}
			}

			// 递减目录
			for {
				// 向上递减一级目录
				if matches := util.RegexFindSubmatch(`(.*)/[^/]+/?$`, currentPath); len(matches) > 0 && len(matches[0]) > 1 {
					currentPath = matches[0][1]
					if currentPath == "" {
						currentPath = "/"
					}
					fuzzURL := baseHost + currentPath
					fuzzURLs = append(fuzzURLs, fuzzURL)
					if fileName != "" {
						fileURL := baseHost + currentPath + "/" + fileName
						fuzzURLs = append(fuzzURLs, fileURL)
					}
				} else {
					break
				}
			}
		}
	}

	return fuzzURLs
}

// generateCombinationFuzz 生成目录组合fuzz URL
func (f *Fuzzer) generateCombinationFuzz(links404 []string, level int) []string {
	var fuzzURLs []string
	var directories []string
	var files []string

	// 提取所有目录和文件
	for _, link := range links404 {
		if matches := util.RegexFindSubmatch(`https?://[^/]+(.*)`, link); len(matches) > 1 {
			path := matches[1][0]
			if path == "" {
				continue
			}

			// 提取目录
			if dirMatches := util.RegexFindSubmatch(`/([^/]+)`, path); len(dirMatches) > 1 {
				for _, match := range dirMatches[1] {
					directories = append(directories, match)
				}
			}

			// 提取文件名
			if !strings.HasSuffix(path, "/") {
				if fileMatches := util.RegexFindSubmatch(`/([^/]+)$`, path); len(fileMatches) > 1 {
					files = append(files, fileMatches[1][0])
				}
			}
		}
	}

	// 去重
	directories = util.RemoveDuplicates(directories)
	files = util.RemoveDuplicates(files)

	// 获取基础主机
	var baseHost string
	if len(links404) > 0 {
		if matches := util.RegexFindSubmatch(`(https?://[^/]+)`, links404[0]); len(matches) > 1 {
			baseHost = matches[1][0]
		}
	}

	// 生成组合URL
	for _, dir := range directories {
		for _, file := range files {
			fuzzURLs = append(fuzzURLs, baseHost+"/"+dir+"/"+file)
		}
	}

	return fuzzURLs
}



// generateBaseDirFuzz 基于BaseDir生成模糊测试URL
func (f *Fuzzer) generateBaseDirFuzz() []string {
	var fuzzURLs []string
	var discoveredPaths []string

	// 从所有发现的链接中提取路径
	for _, link := range f.Crawler.Links {
		// 提取路径部分
		if matches := util.RegexFindSubmatch(`https?://[^/]+(.*)`, link.Url); len(matches) > 0 && len(matches[0]) > 1 {
			path := matches[0][1]
			if path != "" && path != "/" {
				discoveredPaths = append(discoveredPaths, path)
			}
		}
	}

	// 去重
	discoveredPaths = util.RemoveDuplicates(discoveredPaths)

	// 确保BaseDir以http://或https://开头
	baseDir := f.BaseDir
	if !strings.HasPrefix(baseDir, "http://") && !strings.HasPrefix(baseDir, "https://") {
		baseDir = "http://" + baseDir
	}

	// 移除BaseDir末尾的斜杠
	baseDir = strings.TrimSuffix(baseDir, "/")

	// 为每个发现的路径生成模糊测试URL
	for _, path := range discoveredPaths {
		// 确保路径以/开头
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		fuzzURL := baseDir + path
		fuzzURLs = append(fuzzURLs, fuzzURL)
	}

	fmt.Printf("[INFO] 使用BaseDir模式: %s\n", f.BaseDir)
	fmt.Printf("[INFO] 发现路径: %d个\n", len(discoveredPaths))

	return fuzzURLs
}

// testDirectoryURL 测试单个目录URL
func (f *Fuzzer) testDirectoryURL(testURL string) {
	resp, err := f.HTTPClient.Get(testURL)
	if err != nil {
		// 记录错误结果
		f.Crawler.AddFuzzResult(mode.FuzzResult{
			URL:      testURL,
			Method:   "GET",
			Status:   0,
			Size:     0,
			Source:   "directory_fuzz",
			Original: testURL,
			FuzzType: "directory_decreasing",
			Error:    err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	// 读取响应内容
	body := make([]byte, 0)
	if resp.ContentLength > 0 && resp.ContentLength < int64(config.MaxResponseSize) { // 限制响应大小
		body = make([]byte, resp.ContentLength)
		resp.Body.Read(body)
	}

	// 记录测试结果
	result := mode.FuzzResult{
		URL:      testURL,
		Method:   "GET",
		Status:   resp.StatusCode,
		Size:     len(body),
		Source:   "directory_fuzz",
		Original: testURL,
		FuzzType: "directory_decreasing",
		Error:    "",
	}

	// 分析响应内容
	if len(body) > 0 {
		content := string(body)
		result.Title = f.extractTitle(content)

		// 检查是否包含敏感信息
		if f.containsSensitiveInfo(content) {
			result.HasSensitive = true
		}

		// 检查是否为有趣的响应
		if f.isInterestingResponse(resp.StatusCode, content) {
			result.IsInteresting = true
		}
	}

	f.Crawler.AddFuzzResult(result)

	// 输出有趣的结果
	if result.IsInteresting || result.HasSensitive || util.IsSuccessStatusCode(result.Status) {
		fmt.Printf("[FUZZ] %s %s [%d] %s (Type: %s)\n",
			"GET", testURL, result.Status, fmt.Sprintf("%d", result.Size), "directory_decreasing")
	}
}
