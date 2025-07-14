package main

import (
	"fmt"
	"os"

	"github.com/Nbccccc/FinderFuzz/crawler"
)

func main() {
	// 检查依赖
	if err := crawler.CheckDependencies(); err != nil {
		fmt.Printf("[ERROR] 依赖检查失败: %v\n", err)
		os.Exit(1)
	}

	// 运行主程序
	if err := crawler.Run(); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		os.Exit(1)
	}
}
