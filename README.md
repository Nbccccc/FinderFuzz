# FinderFuzz
用于渗透测试的WebFuzz扫描工具
## 
## 功能特性

### 链接爬取

- **深度爬取**: 支持多层级页面递归爬取
- **JS文件分析**: 自动提取和分析JavaScript文件中的API接口
- **链接发现**: 智能识别页面中的所有有效链接

### 敏感信息检测

**该部分误报率较高，采用宁可误报不可错过的原则**

- **多类型检测**: 手机号、邮箱、身份证、JWT Token等
- **密钥识别**: API密钥、访问令牌、数据库密钥等
- **云服务AKSK**: AWS、阿里云、腾讯云、百度云等密钥检测
- **自定义规则**: 支持正则表达式自定义检测规则
### Fuzz

- **目录遍历**: 基于发现的路径进行智能目录模糊测试
- **参数模糊**: 自动识别参数(文件上传参数只配置了一种最常见的情况，可自定义配置)
- **敏感响应检测**: 自动标识包含敏感信息的响应

### 权限检测

- **未授权访问检测**: 发现无需认证即可访问的敏感资源
- **双权限头模式**: 支持同时使用高低权限请求头对比
- **灵活配置**: 支持从文件读取请求头配置


## 使用示例
![image-20250714135853104](https://github.com/Nbccccc/FinderFuzz/blob/main/img/1752472578926.jpg)
![image-20250714135853104](https://github.com/Nbccccc/FinderFuzz/blob/main/img/1752472657322.jpg)
### 基础扫描

```bash
# 基础网页爬取和敏感信息检测
./finderfuzz -u https://example.com

# 指定爬取深度
./finderfuzz -u https://example.com -m 3 -s all

# 设置并发线程数
./finderfuzz -u https://example.com -t 20

# 过滤特定状态码
./finderfuzz -u https://example.com -s 200,403,500
```

### 模糊测试

```bash
# 启用模糊测试
./finderfuzz -u https://example.com -z 3

# 启用参数模糊测试
./finderfuzz -u https://example.com --param-fuzz

```

### 权限检测

```bash
# 未授权访问检测(只使用--read-header是用默认的请求头和指定的请求头进行比较)
./finderfuzz -u https://example.com --unauthority-fuzz --read-headers 1.txt --high-headers 
#同时使用则为高权限头与低权限头进行比较
./finderfuzz -u https://example.com --unauthority-fuzz --read-headers low.txt --high-headers high.txt

--authority-fuzz
则是为了找到有权限才能访问的接口，使用类似上面
```

### 高级配置

```bash
# 使用代理
./finderfuzz -u https://example.com --proxy http://127.0.0.1:8080

# 使用配置文件
./finderfuzz -u https://example.com -c config.yaml

# 生成HTML报告
./finderfuzz -u https://example.com -o report.html

# 设置超时时间
./finderfuzz -u https://example.com --timeout 30

# 自定义配置
./finderfuzz -u https://example.com -i config.yaml
```

## 配置说明

### 配置文件示例 (config.yaml)

```yaml
# FinderFuzz 配置文件示例
# 使用 -i 参数指定此配置文件来覆盖默认配置
#该页面为示例，以下配置皆可修改。部分配置也可，未配置的则为默认
# 基础配置
headers:
  User-Agent: "Custom FinderFuzz Scanner v1.0"
  Authorization: "Bearer your-token-here"
  X-Custom-Header: "custom-value"

proxy: "http://127.0.0.1:8080"
timeout: 15000  # 15秒超时
thread: 20      # 20个线程
max: 200        # 最大爬取200个页面

# JS和URL查找配置
js_find:
  - "(https{0,1}:[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{3}[.]js)"
  - "[\"''`]\\s{0,6}(/{0,1}[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{3}[.]js)"

url_find:
  - "[\"''`]\\s{0,6}(https{0,1}:[-a-zA-Z0-9()@:%_\\+.~#?&//={}]{2,250}?)\\s{0,6}[\"''`]"
  - "/api/[a-zA-Z0-9/_-]+"
  - "/v[0-9]+/[a-zA-Z0-9/_-]+"

# 敏感信息检测配置
info_find:
  phone:
    - "1[3-9]\\d{9}"
    - "\\+86[- ]?1[3-9]\\d{9}"
  email:
    - "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
  jwt:
    - "eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*"

# 云服务AKSK检测
aksk_find:
  aws:
    - "AKIA[0-9A-Z]{16}"
    - "[A-Za-z0-9/+=]{40}"
  aliyun:
    - "LTAI[a-zA-Z0-9]{12,20}"

# 域名和IP检测
cloud_domains:
  - "[a-zA-Z0-9.-]+\\.amazonaws\\.com"
  - "[a-zA-Z0-9.-]+\\.aliyuncs\\.com"
  - "[a-zA-Z0-9.-]+\\.myqcloud\\.com"

domain_find:
  - "https?://([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})"
  - "['\"']([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})['\"']"

ip_find:
  - "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"

# 权限检测配置
unauthorized_keywords:
  - "unauthorized"
  - "forbidden"
  - "access denied"
  - "权限不足"
  - "未授权"
  - "禁止访问"

param_error_keywords:
  - "参数错误"
  - "parameter error"
  - "missing parameter"
  - "参数缺失"
  - "field required"

common_params:
  - "id"
  - "uid"
  - "user_id"
  - "username"
  - "password"
  - "token"
  - "page"
  - "limit"
  - "query"

# 新增的可配置项

# 危险路由关键词
dangerous_keywords:
  - "delete"
  - "remove"
  - "destroy"
  - "logout"
  - "kill"
  - "shutdown"
  - "update"
  - "modify"
  - "reset"
  - "clear"


# API路径提取模式
api_patterns:
  - "[\"']/api/[a-zA-Z0-9/_-]+[\"']"
  - "[\"']/v[0-9]+/[a-zA-Z0-9/_-]+[\"']"
  - "[\"'][a-zA-Z0-9/_-]*\\.php[\"']"
  - "[\"'][a-zA-Z0-9/_-]*\\.jsp[\"']"
  - "[\"']/[a-zA-Z0-9/_-]+[\"']"

# 参数名提取模式
param_name_patterns:
  - "parameter[\\s'\"]*([a-zA-Z_][a-zA-Z0-9_]*)[\\s'\"]*"
  - "param[\\s'\"]*([a-zA-Z_][a-zA-Z0-9_]*)[\\s'\"]*"
  - "field[\\s'\"]*([a-zA-Z_][a-zA-Z0-9_]*)[\\s'\"]*"
  - "missing[\\s'\"]*([a-zA-Z_][a-zA-Z0-9_]*)[\\s'\"]*"
  - "required[\\s'\"]*([a-zA-Z_][a-zA-Z0-9_]*)[\\s'\"]*"

# 文件上传测试配置
file_upload_test_data:
  boundary: "----WebKitFormBoundaryCustomTest123"
  filename: "test.txt"
  content: "This is a custom test file content."
  contentType: "text/plain"

# 文件上传专用请求头
file_upload_headers:
  User-Agent: "Mozilla/5.0 (Custom FinderFuzz Upload Test)"
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  Accept-Encoding: "gzip, deflate"
  Accept-Language: "zh-CN,zh;q=0.9,en;q=0.8"
  X-Upload-Test: "true"

# 响应内容大小阈值
max_response_size: 15000  # 最大响应大小（字节）
min_response_size: 50     # 最小响应大小（字节）

```

### 权限头文件示例

**high_headers.txt** (高权限头):

```
Cookie: auth_token=secret123
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
```

**low_headers.txt** (低权限头):

```
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
```

## 命令行选项

```
用法:
  finderfuzz [选项] -u <目标URL>

基础选项:
  -u <url>              目标URL
  -f <file>             批量URL文件
  -o <path>             结果导出路径
  -h                    显示帮助信息

请求配置:
  -a <agent>            自定义User-Agent
  -c <cookie>           请求Cookie
  -x <proxy>            代理设置
  -i <config>           YAML配置文件

扫描模式:
  -m <mode>             扫描模式 (1:正常 2:深度 3:安全)
  -t <num>              并发线程数 (默认50)
  -time <sec>           超时时间 (默认5秒)
  -max <num>            最大抓取数 (默认1000)
  -s <codes>            状态码过滤

模糊测试:
  --basedir <dir>       模糊测试基础目录
  -z <mode>             404链接模糊测试模式 (1:目录递减 2:二级目录组合 3:三级目录组合)

权限检测:
  --read-headers <file> 低权限请求头文件
  --high-headers <file> 高权限请求头文件
  --authority-fuzz      启用权限检测
  --unauthority-fuzz    启用未授权访问检测
  --param-fuzz          启用参数模糊测试

示例:
  finderfuzz -u https://example.com -s all -m 3 -o result.html
  finderfuzz -u https://example.com -z 3
  finderfuzz -u https://example.com --read-headers auth.txt --authority-fuzz
  finderfuzz -f urls.txt --unauthority-fuzz --read-headers low.txt --high-headers high.txt
  finderfuzz -u https://example.com --param-fuzz
```




**如果这个项目对你有帮助，请给个 ⭐ Star 支持一下！**
感谢[URLFInder](https://github.com/pingc0y/URLFinder)
