package config

import (
	"fmt"
	"os"
	"sync"

	"github.com/Nbccccc/FinderFuzz/mode"
	"gopkg.in/yaml.v3"
)

var (
	// 全局配置
	Conf mode.Config

	// 进度计数器
	Progress int

	// 模糊测试计数器
	FuzzNum int

	// 敏感信息检测正则表达式
	// 手机号码
	Phone = []string{
		`1[3-9]\d{9}`,
		`\+86[- ]?1[3-9]\d{9}`,
		`86[- ]?1[3-9]\d{9}`,
	}

	// 邮箱地址
	Email = []string{
		`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
	}

	// 身份证号
	IDcard = []string{
		`[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]`,
		`[1-9]\d{7}((0\d)|(1[0-2]))(([0|1|2]\d)|3[0-1])\d{3}$`,
	}

	// JWT Token
	Jwt = []string{
		`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`,
		`\bBearer\s+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`,
	}

	// 各种密钥和令牌
	Key = []string{
		// API密钥
		`['"]?(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 认证令牌
		`['"]?(refresh[_-]?token|csrf[_-]?token|xsrf[_-]?token|oauth[_-]?token|bearer[_-]?token)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 密钥类型
		`['"]?(private[_-]?key|public[_-]?key|encryption[_-]?key|signing[_-]?key)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 应用密钥
		`['"]?(client[_-]?secret|app[_-]?secret|session[_-]?key)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 认证方式
		`['"]?(basic[_-]?auth|digest[_-]?auth|ntlm[_-]?auth)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// SSO令牌
		`['"]?(kerberos[_-]?token|saml[_-]?token|openid[_-]?token|cas[_-]?ticket)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 会话和缓存
		`['"]?(session[_-]?id|cookie[_-]?value|cache[_-]?key)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 数据库密钥
		`['"]?(redis|memcached|elasticsearch|mongodb|mysql|postgresql|oracle|sqlite|mssql|mariadb|cassandra|dynamodb|firebase)[_-]?key['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 云服务密钥
		`['"]?(aws|azure|gcp|alibaba|tencent|baidu)[_-]?key['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
	}

	// 密码相关（优化后的正则表达式）
	Password = []string{
		// 常见密码字段
		`['"]?(password|passwd|pwd|pass|secret|credential)['"]?\s*[:=]\s*['"][^'"\s]{6,}['"]`,
		// 认证相关
		`['"]?(auth|login|signin|signon|logon|access)['"]?\s*[:=]\s*['"][^'"\s]{6,}['"]`,
		// 管理员账户
		`['"]?(admin|root|user)['"]?\s*[:=]\s*['"][^'"\s]{6,}['"]`,
	}

	// 用户名相关（优化后的正则表达式）
	Name = []string{
		// 账户信息
		`['"]?(username|account|email)['"]?\s*[:=]\s*['"][^'"\s]{3,}['"]`,
		// 联系方式
		`['"]?(phone|mobile|tel|telephone|cellphone)['"]?\s*[:=]\s*['"][^'"\s]{3,}['"]`,
		// 姓名信息
		`['"]?(name|nickname|realname|fullname)['"]?\s*[:=]\s*['"][^'"\s]{2,}['"]`,
		// 姓名组成
		`['"]?(firstname|lastname|surname|givenname|familyname)['"]?\s*[:=]\s*['"][^'"\s]{2,}['"]`,
		// 显示名称
		`['"]?(displayname|screenname|alias|handle)['"]?\s*[:=]\s*['"][^'"\s]{2,}['"]`,
	}

	// 其他敏感信息（下划线和驼峰命名变体）
	Other = []string{
		// API密钥变体
		`['"]?(api_key|apikey|secret_key|secretkey)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 访问令牌变体
		`['"]?(access_token|accesstoken|auth_token|authtoken)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 客户端密钥变体
		`['"]?(client_secret|clientsecret|app_secret|appsecret)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 刷新令牌变体
		`['"]?(refresh_token|refreshtoken)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// CSRF令牌变体
		`['"]?(csrf_token|csrftoken|xsrf_token|xsrftoken)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// OAuth令牌变体
		`['"]?(oauth_token|oauthtoken|bearer_token|bearertoken)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
		// 会话和Cookie变体
		`['"]?(session_id|sessionid|cookie_value|cookievalue)['"]?\s*[:=]\s*['"][^'"\s]{10,}['"]`,
	}

	//JsFind = []string{
	//	"(https{0,1}:[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{3}[.]js)",
	//	"[\"''`]\\s{0,6}(/{0,1}[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{3}[.]js)",
	//	"=\\s{0,6}[\",'',\"]\\s{0,6}(/{0,1}[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{3}[.]js)",
	//}
	// JsFind JS文件查找正则
	JsFind = []string{
		`(https?:[-a-zA-Z0-9()@:%_\\+.~#?&//=]{0,250}?\.js)`,
		"[\"'`]\\s{0,6}(/?[-a-zA-Z0-9()@:%_\\+.~#?&//=]{0,250}?\\.js)",
		"=\\s{0,6}[\"'`]\\s{0,6}(/?[-a-zA-Z0-9()@:%_\\+.~#?&//=]{0,250}?\\.js)",
	}

	// URL查找正则
	UrlFind = []string{
		"[\"''`]\\s{0,6}(https{0,1}:[-a-zA-Z0-9()@:%_\\+.~#?&//={}]{2,250}?)\\s{0,6}[\"''`]",
		"=\\s{0,6}(https{0,1}:[-a-zA-Z0-9()@:%_\\+.~#?&//={}]{2,250})",
		"[\"''`]\\s{0,6}([#,.]{0,2}/[-a-zA-Z0-9()@:%_\\+.~#?&//={}]{2,250}?)\\s{0,6}[\"''`]",
		"\"([-a-zA-Z0-9()@:%_\\+.~#?&//={}]+?[/]{1}[-a-zA-Z0-9()@:%_\\+.~#?&//={}]+?)\"",
		"href\\s{0,6}=\\s{0,6}[\"''`]{0,1}\\s{0,6}([-a-zA-Z0-9()@:%_\\+.~#?&//={}]{2,250})|action\\s{0,6}=\\s{0,6}[\"''`]{0,1}\\s{0,6}([-a-zA-Z0-9()@:%_\\+.~#?&//={}]{2,250})",
		"/api/[a-zA-Z0-9/_-]+",
		"/v[0-9]+/[a-zA-Z0-9/_-]+",
	}

	// JS文件过滤规则
	JsFiler = []string{
		"www\\.w3\\.org",
		"example\\.com",
		"googleapis\\.com",
		"jquery",
		"bootstrap",
	}

	// URL过滤规则
	UrlFiler = []string{
		".*\\.css$|.*\\.scss$|.*,$|.*\\.jpeg$|.*\\.jpg$|.*\\.png$|.*\\.gif$|.*\\.ico$|.*\\.svg$|.*\\.vue$|.*\\.ts$",
	}

	// 云服务AKSK检测（优化后的正则表达式）
	// AWS Access Key 和 Secret Key
	AWSAKSK = []string{
		`AKIA[0-9A-Z]{16}`, // AWS Access Key ID
		`['"]?aws[_-]?access[_-]?key[_-]?id['"]?\s*[:=]\s*['"]?AKIA[0-9A-Z]{16}['"]?`,
		`['"]?aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]`,
		`[A-Za-z0-9/+=]{40}`, // AWS Secret Access Key
	}

	// 阿里云 AccessKey
	AliyunAKSK = []string{
		`LTAI[a-zA-Z0-9]{12,20}`, // 阿里云 AccessKey ID
		`['"]?access[_-]?key[_-]?id['"]?\s*[:=]\s*['"]?LTAI[a-zA-Z0-9]{12,20}['"]?`,
		`['"]?access[_-]?key[_-]?secret['"]?\s*[:=]\s*['"][a-zA-Z0-9]{30}['"]`,
	}

	// 腾讯云 SecretId 和 SecretKey
	TencentAKSK = []string{
		`AKID[a-zA-Z0-9]{13,20}`, // 腾讯云 SecretId
		`['"]?secret[_-]?id['"]?\s*[:=]\s*['"]?AKID[a-zA-Z0-9]{13,20}['"]?`,
		`['"]?secret[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9]{32}['"]`,
	}

	// 百度云 AccessKey
	BaiduAKSK = []string{
		`['"]?access[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9]{32}['"]`,
		`['"]?secret[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9]{32}['"]`,
	}

	// 华为云 AccessKey
	HuaweiAKSK = []string{
		`['"]?access[_-]?key['"]?\s*[:=]\s*['"][A-Z0-9]{20}['"]`,
		`['"]?secret[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9]{40}['"]`,
	}

	// 云域名检测
	CloudDomains = []string{
		`[a-zA-Z0-9.-]+\.amazonaws\.com`,
		`[a-zA-Z0-9.-]+\.aliyuncs\.com`,
		`[a-zA-Z0-9.-]+\.aliyun\.com`,
		`[a-zA-Z0-9.-]+\.myqcloud\.com`,
		`[a-zA-Z0-9.-]+\.tencentcloudapi\.com`,
		`[a-zA-Z0-9.-]+\.qcloud\.com`,
		`[a-zA-Z0-9.-]+\.baidubce\.com`,
		`[a-zA-Z0-9.-]+\.bcebos\.com`,
		`[a-zA-Z0-9.-]+\.bcehost\.com`,
		`[a-zA-Z0-9.-]+\.hwclouds\.com`,
		`[a-zA-Z0-9.-]+\.huaweicloud\.com`,
		`[a-zA-Z0-9.-]+\.myhwclouds\.com`,
		`[a-zA-Z0-9.-]+\.azure\.com`,
		`[a-zA-Z0-9.-]+\.azurewebsites\.net`,
		`[a-zA-Z0-9.-]+\.cloudapp\.azure\.com`,
		`[a-zA-Z0-9.-]+\.googleapis\.com`,
		`[a-zA-Z0-9.-]+\.googleusercontent\.com`,
		`[a-zA-Z0-9.-]+\.appspot\.com`,
		`[a-zA-Z0-9.-]+\.cloudfunctions\.net`,
	}

	// 危险路由关键词配置
	DangerousKeywords = []string{
		"delete", "del", "remove", "destroy", "logout", "loginout",
		"kill", "shutdown", "reboot", "update", "modify", "create",
		"edit", "change", "reset", "clear", "insert", "import", "enable", "disable",
	}

	// 参数错误提示关键词
	ParamErrorKeywords = []string{
		"参数错误", "参数不正确", "参数缺失", "参数无效", "必需参数", "缺少参数",
		"parameter error", "parameter invalid", "parameter missing", "parameter required",
		"missing parameter", "invalid parameter", "required parameter", "param error",
		"bad parameter", "wrong parameter", "parameter not found", "param not found",
		"参数名错误", "参数名不存在", "未知参数", "不支持的参数",
		"unknown parameter", "unsupported parameter", "parameter not supported",
		"field required", "field missing", "field error", "field invalid",
		"字段错误", "字段缺失", "字段无效", "必填字段",
		"validation error", "validation failed", "校验失败", "验证失败",
	}

	// 常见参数名字典
	CommonParams = []string{
		// 基础参数
		"id", "uid", "user_id", "userId", "user", "username", "name", "email",
		"password", "passwd", "pwd", "pass", "token", "key", "api_key", "apikey",
		"access_token", "accessToken", "auth_token", "authToken", "session", "sessionId",
		// 分页参数
		"page", "pageNum", "pageSize", "limit", "offset", "start", "end", "count",
		"per_page", "perPage", "page_size", "page_num",
		// 查询参数
		"query", "q", "search", "keyword", "keywords", "term", "filter", "sort",
		"order", "orderBy", "order_by", "sortBy", "sort_by", "direction", "dir",
		// 时间参数
		"time", "date", "datetime", "timestamp", "start_time", "end_time",
		"startTime", "endTime", "created_at", "updated_at", "createdAt", "updatedAt",
		// 状态参数
		"status", "state", "type", "category", "tag", "tags", "label", "labels",
		"group", "role", "permission", "level", "priority", "flag", "enabled",
		// 文件参数
		"file", "filename", "path", "url", "link", "src", "source", "target",
		"upload", "download", "attachment", "image", "photo", "picture", "avatar",
		// 数据参数
		"data", "content", "text", "message", "msg", "description", "desc",
		"title", "subject", "body", "value", "val", "param", "params", "args",
		// 配置参数
		"config", "setting", "option", "options", "preference", "preferences",
		"format", "encoding", "charset", "lang", "language", "locale", "timezone",
		// 业务参数
		"action", "method", "operation", "op", "cmd", "command", "function", "func",
		"callback", "redirect", "return_url", "returnUrl", "next", "prev", "back",
		// 验证参数
		"code", "verify_code", "verifyCode", "captcha", "csrf", "csrf_token",
		"nonce", "signature", "sign", "hash", "checksum", "validation",
	}

	// 文件上传测试配置
	FileUploadTestData = map[string]string{
		"boundary":    "----WebKitFormBoundary7MA4YWxkTrZu0gW",
		"filename":    "example.txt",
		"content":     "Hello, this is a test file.",
		"contentType": "text/plain",
	}

	// 文件上传专用请求头
	FileUploadHeaders = map[string]string{
		"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "zh-CN,zh;q=0.9",
	}

	// 域名提取正则
	DomainFind = []string{
		`https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`,
		`['"]([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})['"]`,
		`//([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`,
		`@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`,
	}

	// IP地址提取正则
	IPFind = []string{
		`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
		`['"](?:[0-9]{1,3}\.){3}[0-9]{1,3}['"]`,
	}

	// 模糊测试路径
	JsFuzzPath = []string{
		"login.js", "app.js", "main.js", "config.js", "admin.js",
		"info.js", "open.js", "user.js", "input.js", "list.js",
		"upload.js", "api.js", "common.js", "utils.js", "index.js",
	}

	// 未授权关键词
	UnauthorizedKeywords = []string{
		"unauthorized", "forbidden", "access denied", "permission denied",
		"not authorized", "authentication required", "login required",
		"please login", "please log in", "sign in required",
		"authentication failed", "invalid credentials", "access forbidden",
		"insufficient privileges", "no permission",

		"权限不足", "未授权", "禁止访问", "拒绝访问", "需要登录",
		"请登录", "认证失败", "身份验证失败", "无权限", "访问被拒绝",
		"登录失效", "会话过期", "token过期", "token失效",
		"令牌无效", "令牌过期",
	}

	// 敏感信息检测模式
	SensitivePatterns = []string{
		`password`,
		`secret`,
		`token`,
		`api[_-]?key`,
		`access[_-]?token`,
		`private[_-]?key`,
		`database`,
		`config`,
		`admin`,
		`root`,
		`debug`,
		`error`,
		`exception`,
		`stack[_-]?trace`,
	}

	//API路径提取模式
	APIPatterns = []string{
		`['"](?:/[^\s"'\\]{1,256}|\.{0,2}/[^\s"'\\]{1,256})['"]`,
		`['"][^\s"']{1,64}\?[^\s"']{3,256}['"]`,
		"`[^`]{4,256}/(?:api|v\\d+)/[^`\\s]{4,256}",
		`['"][^\s"']{1,32}(?:['"]\s*\+\s*['"][^\s"']{1,32}){1,3}['"]`,
		`['"]/(?:api|v\d+|graphql|grpc|oauth|auth|sso|login|logout|token|ws|wss)[^\s"']{0,64}['"]`,
		`['"][^\s"']*\.(?:php|jsp|asp|aspx|do|action|cfm|pl)\b[^\s"']*['"]`,
	}
	//APIPatterns = []string{
	//	`['"](?:/(?:[^"'\\/]|\\/)+|(?:\.\.?/)?[\w\-~!$&'()*+,;=:@%\.]+)\.(?:php|jsp|asp|aspx|do|action)\b[^"'\\s]*['"]`,
	//	`['"]/api(?:s)?/[\w\-~!$&'()*+,;=:@%\.\\/]{2,256}['"]`,
	//	`['"]/v\d+/[\w\-~!$&'()*+,;=:@%\.\\/]{2,256}['"]`,
	//	`['"]/[^"'\\s?]{1,64}\?[^"'\\s]{3,256}['"]`,
	//	`['"]/(?:\w+/)?(?:\{\w+\}|:\w+)(?:/(?:\{\w+\}|:\w+)){0,3}['"]`,
	//	`['"]/(?:graphql|grpc|rest|rpc|jsonrpc)[^"'\\s]{0,64}['"]`,
	//	`['"]/\w+\.\w+/\w+(?:/[\w\.]{1,64})?['"]`,
	//	`['"]/(?:oauth|auth|sso|login|logout|token)[^"'\\s]{1,64}['"]`,
	//	`['"]/(?:ws|wss)[^"'\\s]{3,64}['"]`,
	//	`['"]/[\w\-~!$&'()*+,;=:@%\.\/]{2,256}['"]`,
	//	"`[^`]*?/(?:api|v\\d+)/[^`\\s]{4,256}",
	//	`['"][\w\-~!$&'()*+,;=:@%\.\\/]{1,32}(?:['"]\s*\+\s*['"][\w\-~!$&'()*+,;=:@%\.\\/]{1,32}){1,3}['"]`,
	//}
	//APIPatterns = []string{
	//	// API 路径模式
	//	`["']/api/[-a-zA-Z0-9()@:%_\\+~#?&\\/=]{1,256}["']`,
	//	`["']/v\d+/[-a-zA-Z0-9()@:%_\\+~#?&\\/=]{1,256}["']`,
	//	`["'][-a-zA-Z0-9()@:%_\\+~#?&\\/=]*\.(?:php|jsp|asp|aspx)\b[^"']*["']`,
	//	`["']/[-a-zA-Z0-9()@:%_\\+~#?&\\/=]+\?[^"']{3,256}["']`,
	//	`["']/(?!.*\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff|ttf)\b)[-a-zA-Z0-9()@:%_\\+~#?&\\/=]{1,256}["']`,
	//}

	//	`["']/api/[a-zA-Z0-9/_-]+["']`,
	//	`["']/v[0-9]+/[a-zA-Z0-9/_-]+["']`,
	//	`["'][a-zA-Z0-9/_-]*\.php["']`,
	//	`["'][a-zA-Z0-9/_-]*\.jsp["']`,
	//	`["'][a-zA-Z0-9/_-]*\.asp["']`,
	//	`["'][a-zA-Z0-9/_-]*\.aspx["']`,
	//	`["']/[a-zA-Z0-9/_-]*\?[a-zA-Z0-9&=_-]+["']`,
	//	`["']/[a-zA-Z0-9/_-]+["']`,

	// 参数名提取模式
	ParamNamePatterns = []string{
		`parameter[\s'"]*([a-zA-Z_][a-zA-Z0-9_]*)[\s'"]*`,
		`param[\s'"]*([a-zA-Z_][a-zA-Z0-9_]*)[\s'"]*`,
		`field[\s'"]*([a-zA-Z_][a-zA-Z0-9_]*)[\s'"]*`,
		`参数[\s'"]*([a-zA-Z_][a-zA-Z0-9_]*)[\s'"]*`,
		`字段[\s'"]*([a-zA-Z_][a-zA-Z0-9_]*)[\s'"]*`,
		`missing[\s'"]*([a-zA-Z_][a-zA-Z0-9_]*)[\s'"]*`,
		`required[\s'"]*([a-zA-Z_][a-zA-Z0-9_]*)[\s'"]*`,
		`invalid[\s'"]*([a-zA-Z_][a-zA-Z0-9_]*)[\s'"]*`,
	}

	// 有趣的HTTP状态码
	InterestingStatusCodes = []int{401, 403, 500, 502, 503}

	// HTTP方法列表
	HTTPMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

	// Content-Type类型
	ContentTypes = []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data"}

	// 基础Content-Type类型（不包含文件上传）
	BasicContentTypes = []string{"application/json", "application/x-www-form-urlencoded"}

	// 默认User-Agent
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

	// 参数模糊测试User-Agent
	ParamFuzzUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X FinderFuzz) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

	// 响应内容大小阈值
	MaxResponseSize = 10000
	MinResponseSize = 100

	// 互斥锁
	mu sync.Mutex
)

// LoadConfig 从YAML文件加载配置
func LoadConfig(configPath string) error {
	if configPath == "" {
		return nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	err = yaml.Unmarshal(data, &Conf)
	if err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	return nil
}

// InitConfig 初始化默认配置
func InitConfig() {
	if len(Conf.JsFind) == 0 {
		Conf.JsFind = JsFind
	}
	if len(Conf.UrlFind) == 0 {
		Conf.UrlFind = UrlFind
	}
	if len(Conf.JsFiler) == 0 {
		Conf.JsFiler = JsFiler
	}
	if len(Conf.UrlFiler) == 0 {
		Conf.UrlFiler = UrlFiler
	}
	if len(Conf.JsFuzzPath) == 0 {
		Conf.JsFuzzPath = JsFuzzPath
	}

	if Conf.Timeout == 0 {
		Conf.Timeout = 10000 // 默认10秒
	}
	if Conf.Thread == 0 {
		Conf.Thread = 10
	}
	if Conf.Max == 0 {
		Conf.Max = 100
	}

	// 初始化敏感信息查找配置
	if Conf.InfoFind == nil {
		Conf.InfoFind = make(map[string][]string)
	}
	if len(Conf.InfoFind["phone"]) == 0 {
		Conf.InfoFind["phone"] = Phone
	}
	if len(Conf.InfoFind["email"]) == 0 {
		Conf.InfoFind["email"] = Email
	}
	if len(Conf.InfoFind["idcard"]) == 0 {
		Conf.InfoFind["idcard"] = IDcard
	}
	if len(Conf.InfoFind["jwt"]) == 0 {
		Conf.InfoFind["jwt"] = Jwt
	}
	if len(Conf.InfoFind["key"]) == 0 {
		Conf.InfoFind["key"] = Key
	}
	if len(Conf.InfoFind["password"]) == 0 {
		Conf.InfoFind["password"] = Password
	}
	if len(Conf.InfoFind["name"]) == 0 {
		Conf.InfoFind["name"] = Name
	}
	if len(Conf.InfoFind["other"]) == 0 {
		Conf.InfoFind["other"] = Other
	}

	// 初始化AKSK检测配置
	if Conf.AKSKFind == nil {
		Conf.AKSKFind = make(map[string][]string)
	}
	if len(Conf.AKSKFind["aws"]) == 0 {
		Conf.AKSKFind["aws"] = AWSAKSK
	}
	if len(Conf.AKSKFind["aliyun"]) == 0 {
		Conf.AKSKFind["aliyun"] = AliyunAKSK
	}
	if len(Conf.AKSKFind["tencent"]) == 0 {
		Conf.AKSKFind["tencent"] = TencentAKSK
	}
	if len(Conf.AKSKFind["baidu"]) == 0 {
		Conf.AKSKFind["baidu"] = BaiduAKSK
	}
	if len(Conf.AKSKFind["huawei"]) == 0 {
		Conf.AKSKFind["huawei"] = HuaweiAKSK
	}

	// 初始化域名检测配置
	if len(Conf.CloudDomains) == 0 {
		Conf.CloudDomains = CloudDomains
	}
	if len(Conf.DomainFind) == 0 {
		Conf.DomainFind = DomainFind
	}
	if len(Conf.IPFind) == 0 {
		Conf.IPFind = IPFind
	}

	// 初始化未授权关键词配置
	if len(Conf.UnauthorizedKeywords) == 0 {
		Conf.UnauthorizedKeywords = UnauthorizedKeywords
	}

	// 初始化参数模糊测试配置
	if len(Conf.ParamErrorKeywords) == 0 {
		Conf.ParamErrorKeywords = ParamErrorKeywords
	}
	if len(Conf.CommonParams) == 0 {
		Conf.CommonParams = CommonParams
	}

	// 初始化新增的可配置项
	// 危险路由关键词
	if len(Conf.DangerousKeywords) == 0 {
		Conf.DangerousKeywords = DangerousKeywords
	}

	// 敏感信息检测模式
	if Conf.SensitivePatterns == nil {
		Conf.SensitivePatterns = make(map[string][]string)
	}
	if len(Conf.SensitivePatterns["default"]) == 0 {
		Conf.SensitivePatterns["default"] = SensitivePatterns
	}

	// API路径提取模式
	if len(Conf.APIPatterns) == 0 {
		Conf.APIPatterns = APIPatterns
	}

	// 参数名提取模式
	if len(Conf.ParamNamePatterns) == 0 {
		Conf.ParamNamePatterns = ParamNamePatterns
	}

	// 文件上传测试配置
	if Conf.FileUploadTestData == nil {
		Conf.FileUploadTestData = make(map[string]string)
	}
	// 为每个缺失的key填充默认值
	for k, v := range FileUploadTestData {
		if _, exists := Conf.FileUploadTestData[k]; !exists {
			Conf.FileUploadTestData[k] = v
		}
	}

	// 文件上传专用请求头
	if Conf.FileUploadHeaders == nil {
		Conf.FileUploadHeaders = make(map[string]string)
	}
	// 为每个缺失的key填充默认值
	for k, v := range FileUploadHeaders {
		if _, exists := Conf.FileUploadHeaders[k]; !exists {
			Conf.FileUploadHeaders[k] = v
		}
	}

	// 响应内容大小阈值
	if Conf.MaxResponseSize == 0 {
		Conf.MaxResponseSize = MaxResponseSize
	}
	if Conf.MinResponseSize == 0 {
		Conf.MinResponseSize = MinResponseSize
	}
}

// GetProgress 获取当前进度
func GetProgress() int {
	mu.Lock()
	defer mu.Unlock()
	return Progress
}

// SetProgress 设置进度
func SetProgress(p int) {
	mu.Lock()
	defer mu.Unlock()
	Progress = p
}

// IncrementProgress 增加进度
func IncrementProgress() {
	mu.Lock()
	defer mu.Unlock()
	Progress++
}

// ResetProgress 重置进度计数
func ResetProgress() {
	mu.Lock()
	defer mu.Unlock()
	Progress = 0
}

// GetFuzzNum 获取模糊测试数量
func GetFuzzNum() int {
	mu.Lock()
	defer mu.Unlock()
	return FuzzNum
}

// SetFuzzNum 设置模糊测试数量
func SetFuzzNum(num int) {
	mu.Lock()
	defer mu.Unlock()
	FuzzNum = num
}

// IncrementFuzzNum 增加模糊测试数量
func IncrementFuzzNum() {
	mu.Lock()
	defer mu.Unlock()
	FuzzNum++
}

// ResetFuzzNum 重置模糊测试计数
func ResetFuzzNum() {
	mu.Lock()
	defer mu.Unlock()
	FuzzNum = 0
}
