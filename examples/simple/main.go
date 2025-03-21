package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yinziyang/govncproxy"
)

func main() {
	// 配置VNC代理
	localAddr := "0.0.0.0:5901"    // 本地监听地址
	remoteAddr := "127.0.0.1:5900" // 远程VNC服务器地址
	password := "1234"             // 初始密码

	// 创建新的VNC代理实例
	proxy := govncproxy.NewVNCProxy(localAddr, remoteAddr, password)

	// 启动代理
	if err := proxy.Start(); err != nil {
		log.Fatalf("启动VNC代理失败: %v", err)
	}

	log.Printf("VNC代理已启动，监听地址: %s", localAddr)
	log.Printf("初始密码: %s", password)

	// 设置定时修改密码（示例）
	go func() {
		time.Sleep(30 * time.Second)
		newPassword := "5678"
		log.Printf("将要更改密码为: %s", newPassword)
		proxy.SetPassword(newPassword)
	}()

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
