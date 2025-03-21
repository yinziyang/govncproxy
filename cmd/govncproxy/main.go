package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yinziyang/govncproxy"
)

func main() {
	// 定义命令行参数
	localAddr := flag.String("local", "0.0.0.0:5901", "本地监听地址，格式为 host:port")
	remoteAddr := flag.String("remote", "127.0.0.1:5900", "远程VNC服务器地址，格式为 host:port")
	password := flag.String("password", "", "VNC认证密码，默认为空")
	verbose := flag.Bool("verbose", false, "启用详细日志记录")
	idleTimeout := flag.Int("idle-timeout", 0, "空闲超时时间（秒），0表示禁用")

	// 解析命令行参数
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("启动VNC代理 - 本地地址: %s, 远程地址: %s", *localAddr, *remoteAddr)
	if *password != "" {
		log.Printf("已设置密码认证")
	} else {
		log.Printf("警告: 未设置认证密码")
	}

	if *verbose {
		log.Printf("已启用详细日志记录")
	}

	if *idleTimeout > 0 {
		log.Printf("已设置空闲超时: %d秒", *idleTimeout)
	}

	// 创建新的VNC代理实例
	proxy := govncproxy.NewVNCProxy(*localAddr, *remoteAddr, *password)

	// 设置详细日志模式
	proxy.SetVerbose(*verbose)

	// 设置空闲超时
	proxy.SetIdleTimeout(*idleTimeout)

	// 启动代理
	if err := proxy.Start(); err != nil {
		log.Fatalf("启动VNC代理失败: %v", err)
	}

	log.Printf("VNC代理已成功启动，等待客户端连接...")

	// 等待中断信号以优雅地关闭服务器
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("正在关闭VNC代理...")
	if err := proxy.Stop(); err != nil {
		log.Printf("关闭代理时出错: %v", err)
	}
	log.Println("VNC代理已关闭")
}
