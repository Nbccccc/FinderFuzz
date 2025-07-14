package mode

// Link 链接结构体
type Link struct {
	Url      string `json:"url"`
	Status   string `json:"status"`
	Size     string `json:"size"`
	Title    string `json:"title"`
	Redirect string `json:"redirect"`
	Source   string `json:"source"`
	Content  string `json:"content"` // 页面内容摘要
}

// Info 敏感信息结构体
type Info struct {
	Phone    []string `json:"phone"`
	Email    []string `json:"email"`
	IDcard   []string `json:"idcard"`
	JWT      []string `json:"jwt"`
	Key      []string `json:"key"`
	Password []string `json:"password"`
	Name     []string `json:"name"`
	Other    []string `json:"other"`
	Source   string   `json:"source"`
}

// Config 配置文件结构体
type Config struct {
	Headers              map[string]string   `yaml:"headers"`
	Proxy                string              `yaml:"proxy"`
	JsFind               []string            `yaml:"js_find"`
	UrlFind              []string            `yaml:"url_find"`
	JsFiler              []string            `yaml:"js_filter"`
	UrlFiler             []string            `yaml:"url_filter"`
	JsFuzzPath           []string            `yaml:"js_fuzz_path"`
	JsSteps              int                 `yaml:"js_steps"`
	UrlSteps             int                 `yaml:"url_steps"`

	Timeout              int                 `yaml:"timeout"`
	Thread               int                 `yaml:"thread"`
	Max                  int                 `yaml:"max"`
	InfoFind             map[string][]string `yaml:"info_find"`
	DomainFind           []string            `yaml:"domain_find"`
	IPFind               []string            `yaml:"ip_find"`
	CloudDomains         []string            `yaml:"cloud_domains"`
	AKSKFind             map[string][]string `yaml:"aksk_find"`
	UnauthorizedKeywords []string            `yaml:"unauthorized_keywords"`
	ParamErrorKeywords   []string            `yaml:"param_error_keywords"`
	CommonParams         []string            `yaml:"common_params"`
	// 新增的可配置项
	DangerousKeywords    []string            `yaml:"dangerous_keywords"`
	SensitivePatterns    map[string][]string `yaml:"sensitive_patterns"`
	APIPatterns          []string            `yaml:"api_patterns"`
	ParamNamePatterns    []string            `yaml:"param_name_patterns"`
	FileUploadTestData   map[string]string   `yaml:"file_upload_test_data"`
	FileUploadHeaders    map[string]string   `yaml:"file_upload_headers"`
	MaxResponseSize      int                 `yaml:"max_response_size"`
	MinResponseSize      int                 `yaml:"min_response_size"`
}

// FuzzResult 模糊测试结果
type FuzzResult struct {
	URL           string `json:"url"`
	Method        string `json:"method"`
	Status        int    `json:"status"`
	Size          int    `json:"size"`
	Source        string `json:"source"`
	Original      string `json:"original"`
	Payload       string `json:"payload"`
	FuzzType      string `json:"fuzz_type"`
	Error         string `json:"error"`
	Title         string `json:"title"`
	HasSensitive  bool   `json:"has_sensitive"`
	IsInteresting bool   `json:"is_interesting"`
}

// JSFile JS文件结构体
type JSFile struct {
	Url       string   `json:"url"`
	Status    string   `json:"status"`
	Size      string   `json:"size"`
	Source    string   `json:"source"`
	APIs      []string `json:"apis"`
	Sensitive []Info   `json:"sensitive"`
	IsTarget  bool     `json:"is_target"`
}

// DomainInfo 域名信息结构体
type DomainInfo struct {
	Domain    string `json:"domain"`
	IP        string `json:"ip"`
	Type      string `json:"type"`       // internal, external, cloud
	CloudType string `json:"cloud_type"` // aws, aliyun, tencent, etc.
	Source    string `json:"source"`
}

// AuthorityResult 权限检测结果
type AuthorityResult struct {
	URL              string `json:"url"`
	HasAuth          bool   `json:"has_auth"`           // 是否进行了认证请求
	NoAuth           bool   `json:"no_auth"`            // 是否进行了无认证请求
	AuthStatusCode   int    `json:"auth_status_code"`   // 认证请求的状态码
	NoAuthStatusCode int    `json:"noauth_status_code"` // 无认证请求的状态码
	Vulnerable       bool   `json:"vulnerable"`         // 是否存在权限问题
	Reason           string `json:"reason"`             // 检测结果说明
	AuthRequest      string `json:"auth_request"`       // 认证请求数据包
	AuthResponse     string `json:"auth_response"`      // 认证响应数据包
	NoAuthRequest    string `json:"noauth_request"`     // 无认证请求数据包
	NoAuthResponse   string `json:"noauth_response"`    // 无认证响应数据包
}

// UnauthorityResult 未授权访问检测结果
type UnauthorityResult struct {
	URL              string `json:"url"`
	HasAuth          bool   `json:"has_auth"`           // 是否进行了认证请求
	NoAuth           bool   `json:"no_auth"`            // 是否进行了无认证请求
	AuthStatusCode   int    `json:"auth_status_code"`   // 认证请求的状态码
	NoAuthStatusCode int    `json:"noauth_status_code"` // 无认证请求的状态码
	Vulnerable       bool   `json:"vulnerable"`         // 是否存在未授权访问漏洞
	Reason           string `json:"reason"`             // 检测结果说明
	AuthRequest      string `json:"auth_request"`       // 认证请求数据包
	AuthResponse     string `json:"auth_response"`      // 认证响应数据包
	NoAuthRequest    string `json:"noauth_request"`     // 无认证请求数据包
	NoAuthResponse   string `json:"noauth_response"`    // 无认证响应数据包
}

// PrivilegeEscalationResult 未授权访问检测结果（低权限->高权限越权）
type PrivilegeEscalationResult struct {
	URL                string `json:"url"`
	HasLowAuth         bool   `json:"has_low_auth"`          // 是否进行了低权限请求
	HasHighAuth        bool   `json:"has_high_auth"`         // 是否进行了高权限请求
	LowAuthStatusCode  int    `json:"low_auth_status_code"`  // 低权限请求的状态码
	HighAuthStatusCode int    `json:"high_auth_status_code"` // 高权限请求的状态码
	Vulnerable         bool   `json:"vulnerable"`            // 是否存在未授权访问漏洞
	Reason             string `json:"reason"`                // 检测结果说明
	LowAuthRequest     string `json:"low_auth_request"`      // 低权限请求数据包
	LowAuthResponse    string `json:"low_auth_response"`     // 低权限响应数据包
	HighAuthRequest    string `json:"high_auth_request"`     // 高权限请求数据包
	HighAuthResponse   string `json:"high_auth_response"`    // 高权限响应数据包
}

// ParamFuzzResult 参数模糊测试结果
type ParamFuzzResult struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	OriginalStatus   int               `json:"original_status"`
	FuzzedParams     []string          `json:"fuzzed_params"`     // 检测到的可能参数名
	SuccessfulParams []string          `json:"successful_params"` // 成功的参数名
	ErrorHints       []string          `json:"error_hints"`       // 页面中的错误提示
	ParamSource      string            `json:"param_source"`      // 参数来源（error_message, form_field等）
	TestResults      []ParamTestResult `json:"test_results"`      // 具体的测试结果
}

// ParamTestResult 单个参数测试结果
type ParamTestResult struct {
	ParamName    string `json:"param_name"`
	ParamValue   string `json:"param_value"`
	Method       string `json:"method"`
	StatusCode   int    `json:"status_code"`
	ResponseSize int    `json:"response_size"`
	HasChange    bool   `json:"has_change"`    // 响应是否有变化
	ErrorMsg     string `json:"error_msg"`     // 错误信息
	Success      bool   `json:"success"`       // 是否成功找到有效参数
	RequestData  string `json:"request_data"`  // HTTP请求包数据
	ResponseData string `json:"response_data"` // HTTP响应包数据
}
