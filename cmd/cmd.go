package cmd

import (
	"flag"
	"fmt"
	"os"
)

// Args 命令行参数结构体
type Args struct {
	UserAgent       string // 自定义User-Agent
	BaseURL         string // 自定义基础URL路径
	BaseDir         string // 模糊测试基础目录
	Cookie          string // 请求Cookie
	Domain          string // 指定域名（支持正则）
	URLFile         string // 批量URL文件路径
	Help            bool   // 显示帮助信息
	Config          bool   // 是否使用配置文件
	ConfigFile      string // 配置文件路径
	Mode            string // 抓取模式
	Max             int    // 最大抓取数
	Output          string // 结果导出路径
	StatusCode      string // 状态码过滤
	Thread          int    // 线程数
	Timeout         int    // 超时时间
	URL             string // 目标URL
	Proxy           string // 代理设置
	Fuzz            bool   // 是否启用模糊测试
	FuzzMode        int    // 模糊测试模式
	ReadHeaders     string // 低权限请求头文件
	HighHeaders     string // 高权限请求头文件
	AuthorityFuzz   bool   // 权限检测模式
	UnauthorityFuzz bool   // 未授权访问检测模式
	ParamFuzz       bool   // 参数模糊测试模式
}

// 命令行参数变量
var (
	// 字符串类型参数
	A  string // User-Agent请求头
	B  string // 基础URL路径
	BD string // 模糊测试基础目录
	C  string // 请求Cookie
	D  string // 指定域名（支持正则）
	F  string // 批量URL文件路径
	I  string // YAML配置文件路径
	O  string // 结果导出路径
	S  string // 状态码过滤
	U  string // 目标URL
	X  string // 代理设置
	RH string // 低权限请求头文件
	HH string // 高权限请求头文件

	// 布尔类型参数
	H   bool // 显示帮助信息
	AF  bool // 权限检测模式
	UAF bool // 未授权访问检测模式
	PF  bool // 参数模糊测试模式

	// 整数类型参数
	M  int // 抓取模式
	MA int // 最大抓取数
	T  int // 线程数
	TI int // 超时时间
	Z  int // 模糊测试模式
)

// Parse 解析命令行参数
func Parse() {
	// 基础参数
	flag.StringVar(&A, "a", "", "自定义User-Agent请求头")
	flag.StringVar(&B, "b", "", "自定义基础URL路径")
	flag.StringVar(&C, "c", "", "请求Cookie")
	flag.StringVar(&D, "d", "", "指定域名（支持正则表达式）")
	flag.StringVar(&F, "f", "", "批量URL文件路径")
	flag.BoolVar(&H, "h", false, "显示帮助信息")
	flag.StringVar(&I, "i", "", "YAML配置文件路径")
	flag.StringVar(&O, "o", "", "结果导出路径（支持csv、json、html格式）")
	flag.StringVar(&S, "s", "", "状态码过滤（逗号分隔，all显示全部）")
	flag.StringVar(&U, "u", "", "目标URL")
	flag.StringVar(&X, "x", "", "代理设置（格式: http://user:pass@host:port）")

	// 模式和性能参数
	flag.IntVar(&M, "m", 1, "抓取模式：\n\t1 - 正常模式\n\t2 - 深度模式\n\t3 - 安全模式")
	flag.IntVar(&MA, "max", 1000, "最大抓取数量")
	flag.IntVar(&T, "t", 50, "并发线程数")
	flag.IntVar(&TI, "time", 5, "超时时间（秒）")

	// 模糊测试参数
	flag.StringVar(&BD, "basedir", "", "模糊测试基础目录")
	flag.IntVar(&Z, "z", 0, "404链接模糊测试模式：\n\t1 - 目录递减\n\t2 - 二级目录组合\n\t3 - 三级目录组合")

	// 权限检测参数
	flag.StringVar(&RH, "read-headers", "", "低权限请求头文件（key:value格式）")
	flag.StringVar(&HH, "high-headers", "", "高权限请求头文件（key:value格式）")
	flag.BoolVar(&AF, "authority-fuzz", false, "启用权限检测")
	flag.BoolVar(&UAF, "unauthority-fuzz", false, "启用未授权访问检测")
	flag.BoolVar(&PF, "param-fuzz", false, "启用参数模糊测试（检测参数错误提示并动态fuzz参数）")

	flag.Usage = usage
	flag.Parse()
}

// ParseArgs 解析命令行参数并返回Args结构体
func ParseArgs() *Args {
	Parse()

	args := &Args{
		UserAgent:       A,
		BaseURL:         B,
		BaseDir:         BD,
		Cookie:          C,
		Domain:          D,
		URLFile:         F,
		Help:            H,
		Config:          I != "",
		ConfigFile:      I,
		Max:             MA,
		Output:          O,
		StatusCode:      S,
		Thread:          T,
		Timeout:         TI,
		URL:             U,
		Proxy:           X,
		Fuzz:            Z > 0 || BD != "",
		FuzzMode:        Z,
		ReadHeaders:     RH,
		HighHeaders:     HH,
		AuthorityFuzz:   AF,
		UnauthorityFuzz: UAF,
		ParamFuzz:       PF,
	}

	// 设置抓取模式
	switch M {
	case 1:
		args.Mode = "normal"
	case 2:
		args.Mode = "thorough"
	case 3:
		args.Mode = "security"
	default:
		args.Mode = "normal"
	}

	// 参数验证
	validateArgs(args)

	return args
}

// validateArgs 验证命令行参数
func validateArgs(args *Args) {
	// 权限检测参数验证
	if args.AuthorityFuzz || args.UnauthorityFuzz {
		if args.ReadHeaders == "" && args.Cookie == "" {
			fmt.Fprintf(os.Stderr, "错误: 权限检测功能需要配合 --read-headers 或 -c 参数使用\n")
			os.Exit(1)
		}
	}

	// 高权限头文件验证
	if args.HighHeaders != "" {
		if !args.AuthorityFuzz && !args.UnauthorityFuzz {
			fmt.Fprintf(os.Stderr, "错误: --high-headers 参数需要配合权限检测功能使用\n")
			os.Exit(1)
		}
		if args.ReadHeaders == "" && args.Cookie == "" {
			fmt.Fprintf(os.Stderr, "错误: 使用 --high-headers 时需要指定低权限请求头\n")
			os.Exit(1)
		}
	}

	// 防止同时使用两种权限检测模式
	if args.AuthorityFuzz && args.UnauthorityFuzz {
		fmt.Fprintf(os.Stderr, "错误: 权限检测和未授权访问检测不能同时使用\n")
		os.Exit(1)
	}

	// 请求头文件优先级处理
	if args.ReadHeaders != "" {
		if args.UserAgent != "" {
			fmt.Printf("[WARN] 使用请求头文件时，User-Agent参数将被忽略\n")
			args.UserAgent = ""
		}
		if args.Cookie != "" {
			fmt.Printf("[WARN] 使用请求头文件时，Cookie参数将被忽略\n")
			args.Cookie = ""
		}
	}
}

// ShowHelp 显示帮助信息
func ShowHelp() {
	usage()
}

// usage 打印帮助信息
func usage() {
	fmt.Fprintf(os.Stderr, `FinderFuzz - 用于渗透测试的WebFuzz扫描工具

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

`)
}
