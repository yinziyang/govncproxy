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
	initialPassword := "1234"      // 初始密码

	// 创建新的VNC代理实例
	proxy := govncproxy.NewVNCProxy(localAddr, remoteAddr, initialPassword)

	// 启动代理
	if err := proxy.Start(); err != nil {
		log.Fatalf("启动VNC代理失败: %v", err)
	}

	log.Printf("VNC代理已启动，监听地址: %s", localAddr)
	log.Printf("初始密码: %s", initialPassword)

	// 设置自动密码轮换
	go autoRotatePassword(proxy)

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

// autoRotatePassword 定期自动更改密码
func autoRotatePassword(proxy *govncproxy.VNCProxy) {
	// 定义密码轮换间隔
	rotationInterval := 2 * time.Minute

	// 定义一组预设密码
	passwords := []string{
		"password1",
		"password2",
		"password3",
		"password4",
	}

	passwordIndex := 0
	ticker := time.NewTicker(rotationInterval)
	defer ticker.Stop()

	for range ticker.C {
		// 选择下一个密码
		passwordIndex = (passwordIndex + 1) % len(passwords)
		newPassword := passwords[passwordIndex]

		log.Printf("正在轮换密码，新密码: %s", newPassword)
		proxy.SetPassword(newPassword)
	}
}
