# GoVNCProxy

GoVNCProxy 是一个基于 Go 语言实现的 VNC 代理库，它可以将没有密码认证的 VNC 服务代理为包含 RFB 认证的 VNC 代理。这个库允许你通过密码保护原本不需要密码的 VNC 服务，并且支持动态修改密码和优雅关闭。

## 特性

- 将无密码 VNC 服务代理为带 RFB 认证的 VNC 服务
- 支持动态修改密码
- 支持优雅关闭代理服务
- 自动断开使用旧密码的客户端连接
- 高性能的并发处理
- 支持命令行参数配置
- 支持空闲超时断开连接
- 支持详细日志记录

## 安装

### 作为库使用

```bash
go get github.com/yinziyang/govncproxy
```

### 作为命令行工具安装

```bash
go install github.com/yinziyang/govncproxy/cmd/govncproxy@latest
```

## 命令行用法

```bash
# 基本用法
govncproxy -local 0.0.0.0:5901 -remote 127.0.0.1:5900 -password 1234

# 启用空闲超时（5分钟无活动自动断开）
govncproxy -local 0.0.0.0:5901 -remote 127.0.0.1:5900 -password 1234 -idle-timeout 300

# 启用详细日志记录
govncproxy -local 0.0.0.0:5901 -remote 127.0.0.1:5900 -password 1234 -verbose

# 查看帮助
govncproxy -h
```

### 可用参数

- `-local` : 本地监听地址，默认为 `0.0.0.0:5901`
- `-remote` : 远程 VNC 服务器地址，默认为 `127.0.0.1:5900`
- `-password` : VNC 认证密码，默认为空
- `-idle-timeout` : 空闲超时时间（秒），当客户端与代理之间在指定时间内无数据交互时自动断开连接，0表示禁用（默认）
- `-verbose` : 启用详细日志记录，默认为禁用

## 作为库使用

```go
package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/yinziyang/govncproxy"
)

func main() {
    // 配置VNC代理
    localAddr := "0.0.0.0:5901"  // 本地监听地址
    remoteAddr := "127.0.0.1:5900"  // 远程VNC服务器地址
    password := "1234"  // 初始密码

    // 创建新的VNC代理实例
    proxy := govncproxy.NewVNCProxy(localAddr, remoteAddr, password)
    
    // 设置空闲超时（5分钟）
    proxy.SetIdleTimeout(300)
    
    // 启用详细日志记录
    proxy.SetVerbose(true)

    // 启动代理
    if err := proxy.Start(); err != nil {
        log.Fatalf("启动VNC代理失败: %v", err)
    }

    log.Printf("VNC代理已启动，监听地址: %s", localAddr)

    // 等待中断信号以优雅地关闭服务器
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan

    log.Println("正在关闭VNC代理...")
    proxy.Stop()
    log.Println("VNC代理已关闭")
}
```

## API 参考

### 创建新代理

```go
// 创建新的VNC代理实例
proxy := govncproxy.NewVNCProxy(localAddr, remoteAddr, password)
```

参数:
- `localAddr`: 本地监听地址，如 "0.0.0.0:5901" 或 "127.0.0.1:5901"
- `remoteAddr`: 远程 VNC 服务器地址，如 "127.0.0.1:5900"
- `password`: 初始密码

### 启动代理

```go
// 启动代理服务（会阻塞）
err := proxy.Start()
```

### 停止代理

```go
// 优雅地停止代理服务
err := proxy.Stop()
```

### 修改密码

```go
// 动态修改密码（会断开使用旧密码的客户端）
proxy.SetPassword("newpassword")
```

### 设置空闲超时

```go
// 设置空闲超时时间（秒），0表示禁用
proxy.SetIdleTimeout(300)  // 5分钟无活动自动断开
```

### 设置详细日志

```go
// 启用或禁用详细日志记录
proxy.SetVerbose(true)
```

## 示例

查看 [examples](./examples) 目录获取更多使用示例：

- [simple](./examples/simple): 基本用法示例
- [auto_rotate_password](./examples/auto_rotate_password): 自动轮换密码示例

## 项目结构

```
govncproxy/
├── cmd/
│   └── govncproxy/    # 命令行工具
│       └── main.go
├── examples/          # 示例代码
│   ├── auto_rotate_password/
│   └── simple/
├── vncproxy.go        # 核心库代码
├── LICENSE
└── README.md
```