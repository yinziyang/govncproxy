package govncproxy

import (
	"bytes"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	RFB_VERSION            = "RFB 003.008\n" // RFB协议版本
	RFB_AUTH_FAILED        = 1               // 认证失败代码
	RFB_AUTH_SUCCESS       = 0               // 认证成功代码
	SECURITY_TYPE_VNC      = 2               // VNC认证安全类型
	SECURITY_TYPE_NONE     = 1               // 无认证安全类型
	CHALLENGE_SIZE         = 16              // VNC认证挑战大小
	SECURITY_HANDSHAKE_LEN = 1 + 3           // 1字节安全类型数量 + 3字节填充
)

// ConnectionInfo 存储连接信息
type ConnectionInfo struct {
	ClientConn   net.Conn
	ServerConn   net.Conn
	ClientAddr   string
	AuthPassword string
	Done         chan struct{}
	LastActivity time.Time   // 最近活动时间
	IdleTimer    *time.Timer // 空闲计时器
	CloseReason  string      // 连接关闭原因
	CloseMutex   sync.Mutex  // 保护连接关闭状态的互斥锁
	Closed       bool        // 连接是否已关闭
}

// SafeClose 安全地关闭连接
func (ci *ConnectionInfo) SafeClose() {
	ci.CloseMutex.Lock()
	defer ci.CloseMutex.Unlock()

	if !ci.Closed {
		ci.Closed = true
		close(ci.Done)
	}
}

// VNCProxy 是VNC代理的主要结构
type VNCProxy struct {
	// 配置
	localAddr     string
	remoteAddr    string
	password      string
	verbose       bool
	idleTimeout   int // 空闲超时（秒），0表示禁用
	listener      net.Listener
	stopChan      chan struct{}
	passwordMutex *sync.RWMutex

	// 活跃连接管理
	activeConns map[string][]*ConnectionInfo
	connsMutex  *sync.Mutex

	// 连接统计
	totalConnections int
	statsMutex       *sync.Mutex

	// 运行状态
	running      bool
	runningMutex *sync.Mutex
}

// NewVNCProxy 创建一个新的VNC代理实例
func NewVNCProxy(localAddr, remoteAddr, password string) *VNCProxy {
	return &VNCProxy{
		localAddr:        localAddr,
		remoteAddr:       remoteAddr,
		password:         password,
		verbose:          false,
		idleTimeout:      0, // 默认禁用空闲超时
		passwordMutex:    &sync.RWMutex{},
		stopChan:         make(chan struct{}),
		activeConns:      make(map[string][]*ConnectionInfo),
		connsMutex:       &sync.Mutex{},
		totalConnections: 0,
		statsMutex:       &sync.Mutex{},
		running:          false,
		runningMutex:     &sync.Mutex{},
	}
}

func (p *VNCProxy) GetPassword() string {
	p.passwordMutex.RLock()
	password := p.password
	p.passwordMutex.RUnlock()
	return password
}

// SetPassword 设置新的密码并断开使用旧密码的连接
func (p *VNCProxy) SetPassword(newPassword string) {
	p.passwordMutex.Lock()
	oldPassword := p.password
	p.password = newPassword
	p.passwordMutex.Unlock()

	log.Printf("密码已从 %s 更改为 %s", oldPassword, newPassword)

	// 断开使用旧密码的客户端
	p.disconnectClientsWithPassword(oldPassword)
}

// SetVerbose 设置详细日志模式
func (p *VNCProxy) SetVerbose(verbose bool) {
	p.verbose = verbose
}

// logVerbose 仅在详细模式下记录日志
func (p *VNCProxy) logVerbose(format string, v ...interface{}) {
	if p.verbose {
		log.Printf(format, v...)
	}
}

// GetConnectionsCount 获取当前活跃连接数和总连接数
func (p *VNCProxy) GetConnectionsCount() (active int, total int) {
	p.connsMutex.Lock()
	activeCount := 0
	for _, conns := range p.activeConns {
		activeCount += len(conns)
	}
	p.connsMutex.Unlock()

	p.statsMutex.Lock()
	totalCount := p.totalConnections
	p.statsMutex.Unlock()

	return activeCount, totalCount
}

// GetConnectionStats 获取完整的连接统计信息
func (p *VNCProxy) GetConnectionStats() map[string]interface{} {
	p.connsMutex.Lock()
	activeConnections := 0
	clientIPs := make(map[string]int)

	for ip, conns := range p.activeConns {
		count := len(conns)
		activeConnections += count
		clientIPs[ip] = count
	}
	p.connsMutex.Unlock()

	p.statsMutex.Lock()
	totalConnections := p.totalConnections
	p.statsMutex.Unlock()

	return map[string]interface{}{
		"active_connections":            activeConnections,
		"total_connections_since_start": totalConnections,
		"client_ips":                    clientIPs,
	}
}

// SetIdleTimeout 设置空闲超时时间（秒）
// 如果设置为0，则禁用空闲超时功能
func (p *VNCProxy) SetIdleTimeout(seconds int) {
	if seconds < 0 {
		seconds = 0
	}
	p.idleTimeout = seconds
	if seconds > 0 {
		log.Printf("已设置空闲超时: %d秒", seconds)
	} else {
		log.Printf("已禁用空闲超时")
	}
}

// GetIdleTimeout 获取当前空闲超时设置（秒）
func (p *VNCProxy) GetIdleTimeout() int {
	return p.idleTimeout
}

// Start 启动VNC代理服务
func (p *VNCProxy) Start() error {
	p.runningMutex.Lock()
	if p.running {
		p.runningMutex.Unlock()
		return fmt.Errorf("代理已在运行中")
	}
	p.running = true
	p.runningMutex.Unlock()

	// 设置日志
	log.SetFlags(log.Ldate | log.Ltime)
	log.Printf("启动VNC代理，本地地址: %s，远程地址: %s", p.localAddr, p.remoteAddr)

	// 监听传入连接
	var err error
	p.listener, err = net.Listen("tcp", p.localAddr)
	if err != nil {
		return fmt.Errorf("设置监听器失败: %v", err)
	}

	// 启动定期输出统计信息的 goroutine
	if p.verbose {
		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()

			for {
				select {
				case <-p.stopChan:
					return
				case <-ticker.C:
					stats := p.GetConnectionStats()
					activeCount := stats["active_connections"].(int)
					totalCount := stats["total_connections_since_start"].(int)
					clientIPs := stats["client_ips"].(map[string]int)

					log.Printf("连接统计 - 当前活跃连接: %d", activeCount)
					if p.verbose {
						log.Printf("自启动以来的总连接数: %d", totalCount)
						if len(clientIPs) > 0 {
							log.Printf("按IP地址的活跃连接分布:")
							for ip, count := range clientIPs {
								log.Printf("  %s: %d个连接", ip, count)
							}
						}
					}
				}
			}
		}()
	}

	go p.acceptConnections()

	return nil
}

// acceptConnections 接受并处理新的连接
func (p *VNCProxy) acceptConnections() {
	defer p.listener.Close()

	for {
		select {
		case <-p.stopChan:
			return
		default:
			// 设置接受超时，以便能够检查停止信号
			p.listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))

			conn, err := p.listener.Accept()
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					// 这只是一个超时，继续检查停止通道
					continue
				}
				log.Printf("接受连接失败: %v", err)
				continue
			}

			// 每个连接在新的goroutine中处理
			go p.handleConnection(conn)
		}
	}
}

// Stop 停止VNC代理服务
func (p *VNCProxy) Stop() error {
	p.runningMutex.Lock()
	defer p.runningMutex.Unlock()

	if !p.running {
		return fmt.Errorf("代理未运行")
	}

	// 获取最终连接统计信息
	stats := p.GetConnectionStats()
	activeCount := stats["active_connections"].(int)
	totalCount := stats["total_connections_since_start"].(int)

	log.Printf("VNC代理停止 - 最终统计 - 当前活跃连接: %d", activeCount)
	if p.verbose {
		log.Printf("服务期间总连接数: %d", totalCount)
	}

	// 发送停止信号
	close(p.stopChan)

	// 关闭所有活跃连接
	p.disconnectAllClients()

	p.running = false
	return nil
}

// disconnectAllClients 断开所有客户端连接
func (p *VNCProxy) disconnectAllClients() {
	p.connsMutex.Lock()
	defer p.connsMutex.Unlock()

	totalConnections := 0
	for ip, connections := range p.activeConns {
		totalConnections += len(connections)
		for _, conn := range connections {
			log.Printf("正在关闭来自 %s 的连接", conn.ClientAddr)
			conn.CloseReason = "代理服务停止"
			conn.SafeClose()
		}
		delete(p.activeConns, ip)
	}

	log.Printf("已断开所有客户端连接，共 %d 个", totalConnections)
}

// disconnectClientsWithPassword 断开使用指定密码的客户端连接
func (p *VNCProxy) disconnectClientsWithPassword(password string) {
	p.connsMutex.Lock()
	defer p.connsMutex.Unlock()

	for ip, connections := range p.activeConns {
		var remainingConns []*ConnectionInfo

		for _, conn := range connections {
			if conn.AuthPassword == password {
				log.Printf("由于密码更改，正在关闭来自 %s 的连接", conn.ClientAddr)
				// 设置关闭原因
				conn.CloseReason = "密码已更改"
				// 发送连接关闭信号
				conn.SafeClose()
				// 实际连接关闭将在handleConnection goroutine中发生
			} else {
				remainingConns = append(remainingConns, conn)
			}
		}

		if len(remainingConns) == 0 {
			delete(p.activeConns, ip)
		} else {
			p.activeConns[ip] = remainingConns
		}
	}
}

// removeConnection 从活跃连接映射中移除连接
func (p *VNCProxy) removeConnection(clientAddr string, connInfo *ConnectionInfo) {
	p.connsMutex.Lock()
	defer p.connsMutex.Unlock()

	p.logVerbose("正在移除客户端 %s 的连接", clientAddr)

	connections, exists := p.activeConns[clientAddr]
	if !exists {
		p.logVerbose("未找到客户端 %s 的连接", clientAddr)
		return
	}

	var remainingConns []*ConnectionInfo
	var removedConn *ConnectionInfo

	for _, conn := range connections {
		if conn != connInfo {
			remainingConns = append(remainingConns, conn)
		} else {
			removedConn = conn
		}
	}

	if removedConn == nil {
		p.logVerbose("在活跃连接列表中未找到要移除的连接: %s", clientAddr)
		return
	}

	if len(remainingConns) == 0 {
		delete(p.activeConns, clientAddr)
		log.Printf("IP %s 的所有连接已移除", clientAddr)
	} else {
		p.activeConns[clientAddr] = remainingConns
		log.Printf("IP %s 的一个连接已移除，剩余 %d 个连接", clientAddr, len(remainingConns))
	}
}

// handleConnection 处理客户端连接
func (p *VNCProxy) handleConnection(clientConn net.Conn) {
	// 增加总连接计数
	p.statsMutex.Lock()
	p.totalConnections++
	currentTotal := p.totalConnections
	p.statsMutex.Unlock()

	// 记录客户端连接
	clientAddr := clientConn.RemoteAddr().String()
	log.Printf("客户端已连接: %s (总连接数: #%d)", clientAddr, currentTotal)

	connStart := time.Now()

	// 创建连接信息
	connInfo := &ConnectionInfo{
		ClientConn:   clientConn,
		ClientAddr:   clientAddr,
		Done:         make(chan struct{}),
		LastActivity: time.Now(),
		CloseReason:  "",
		CloseMutex:   sync.Mutex{},
		Closed:       false,
	}

	// safeCloseConnection 安全地关闭连接
	safeCloseConnection := func() {
		// 调用连接信息对象的SafeClose方法
		connInfo.SafeClose()

		// 从活动连接列表中移除此连接
		p.removeConnection(clientAddr, connInfo)
	}

	// 检查密码是否为空
	p.passwordMutex.RLock()
	passwordEmpty := p.password == ""
	p.passwordMutex.RUnlock()

	var authenticated bool
	var usedPassword string
	var err error

	if passwordEmpty {
		// 如果密码为空，跳过认证
		authenticated = true
		usedPassword = ""

		// 仍然需要处理RFB协议握手，但不进行实际认证
		if err := p.performRFBHandshakeWithoutAuth(clientConn); err != nil {
			log.Printf("%s 的RFB握手错误: %v", clientAddr, err)
			clientConn.Close()
			return
		}
	} else {
		// 执行RFB握手和认证
		authenticated, usedPassword, err = p.performRFBAuthentication(clientConn)
		if err != nil {
			log.Printf("%s 的RFB认证错误: %v", clientAddr, err)
			clientConn.Close()
			return
		}

		if !authenticated {
			log.Printf("%s 认证失败", clientAddr)
			clientConn.Close()
			return
		}
	}

	// 存储用于认证的密码（如果有）
	connInfo.AuthPassword = usedPassword
	if passwordEmpty {
		log.Printf("%s 无需密码认证直接通过", clientAddr)
	} else {
		log.Printf("%s 使用密码 %s 认证成功", clientAddr, usedPassword)
	}

	// 连接到远程服务器
	serverConn, err := net.Dial("tcp", p.remoteAddr)
	if err != nil {
		log.Printf("连接到远程服务器 %s 失败: %v", p.remoteAddr, err)
		clientConn.Close()
		return
	}

	// 存储服务器连接
	connInfo.ServerConn = serverConn

	// 注册连接
	p.connsMutex.Lock()
	if _, exists := p.activeConns[clientAddr]; !exists {
		p.activeConns[clientAddr] = []*ConnectionInfo{}
	}
	p.activeConns[clientAddr] = append(p.activeConns[clientAddr], connInfo)
	p.connsMutex.Unlock()

	// 设置空闲超时
	p.setupIdleTimeout(connInfo)

	// 现在我们需要与服务器执行协议握手
	// 并正确中继初始消息
	if err := p.relayInitialHandshake(clientConn, serverConn); err != nil {
		log.Printf("初始握手中继期间出错: %v", err)
		safeCloseConnection()
		clientConn.Close()
		serverConn.Close()
		p.removeConnection(clientAddr, connInfo)
		return
	}

	// 确保连接在完成时关闭
	defer func() {
		connDuration := time.Since(connStart)
		// 停止空闲超时计时器
		if connInfo.IdleTimer != nil {
			connInfo.IdleTimer.Stop()
		}

		// 安全关闭连接
		safeCloseConnection()
		serverConn.Close()
		clientConn.Close()
		p.removeConnection(clientAddr, connInfo)

		// 根据关闭原因记录不同的日志信息
		if connInfo.CloseReason != "" {
			log.Printf("客户端断开连接: %s，原因: %s，连接持续时间: %s", clientAddr, connInfo.CloseReason, connDuration)
		} else {
			log.Printf("客户端断开连接: %s，连接持续时间: %s", clientAddr, connDuration)
		}
	}()

	// 使用WaitGroup等待两个goroutine完成
	var wg sync.WaitGroup
	wg.Add(2)

	// 将数据从客户端复制到服务器
	go func() {
		defer wg.Done()
		buffer := make([]byte, 32*1024)
		for {
			select {
			case <-connInfo.Done:
				// 根据关闭原因显示不同的日志
				if connInfo.CloseReason != "" {
					log.Printf("客户端连接正在关闭 (%s): %s", connInfo.CloseReason, clientAddr)
				} else {
					log.Printf("客户端连接正在关闭: %s", clientAddr)
				}
				return
			default:
				// 检查连接是否已关闭
				connInfo.CloseMutex.Lock()
				if connInfo.Closed {
					connInfo.CloseMutex.Unlock()
					return
				}
				connInfo.CloseMutex.Unlock()

				// 更新读取开始时间
				dataTransferStartTime := time.Now()

				// 每次读取前重置截止时间
				clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
				n, err := clientConn.Read(buffer)

				// 计算读取耗时
				dataTransferTime := time.Since(dataTransferStartTime)

				if err != nil {
					// 再次检查连接是否已关闭，避免记录已关闭连接的错误
					connInfo.CloseMutex.Lock()
					alreadyClosed := connInfo.Closed
					connInfo.CloseMutex.Unlock()

					if !alreadyClosed {
						if err != io.EOF {
							log.Printf("从客户端 %s 读取时出错: %v", clientAddr, err)
						} else {
							log.Printf("客户端连接已关闭: %s", clientAddr)
						}
						// 设置客户端主动断开的关闭原因
						if err == io.EOF {
							connInfo.CloseReason = "客户端主动断开"
						} else {
							connInfo.CloseReason = fmt.Sprintf("读取错误: %v", err)
						}
						safeCloseConnection()
					}
					return
				}

				// 如果读取用时较长，重置空闲计时器但不更新活动时间
				// 这避免了因为读取等待时间过长而触发空闲超时
				if dataTransferTime > time.Second {
					p.logVerbose("客户端 %s 的读取操作耗时 %.2f 秒", clientAddr, dataTransferTime.Seconds())
					if p.idleTimeout > 0 && connInfo.IdleTimer != nil {
						connInfo.IdleTimer.Reset(time.Duration(p.idleTimeout) * time.Second)
					}
				} else {
					// 仅在数据实际传输时更新活动时间
					p.updateActivity(connInfo)
				}

				// 检查连接是否已关闭
				connInfo.CloseMutex.Lock()
				if connInfo.Closed {
					connInfo.CloseMutex.Unlock()
					return
				}
				connInfo.CloseMutex.Unlock()

				// 开始写入的时间
				writeStartTime := time.Now()

				// 写入服务器
				_, err = serverConn.Write(buffer[:n])

				// 计算写入耗时
				writeTime := time.Since(writeStartTime)

				if err != nil {
					// 再次检查连接是否已关闭
					connInfo.CloseMutex.Lock()
					alreadyClosed := connInfo.Closed
					connInfo.CloseMutex.Unlock()

					if !alreadyClosed {
						log.Printf("写入 %s 的服务器时出错: %v", clientAddr, err)
						connInfo.CloseReason = fmt.Sprintf("服务器写入错误: %v", err)
						safeCloseConnection()
					}
					return
				}

				// 如果写入用时较长，重置空闲计时器
				if writeTime > time.Second {
					p.logVerbose("写入服务器的操作耗时 %.2f 秒", writeTime.Seconds())
					if p.idleTimeout > 0 && connInfo.IdleTimer != nil {
						connInfo.IdleTimer.Reset(time.Duration(p.idleTimeout) * time.Second)
					}
				}
			}
		}
	}()

	// 将数据从服务器复制到客户端
	go func() {
		defer wg.Done()
		buffer := make([]byte, 32*1024)
		for {
			select {
			case <-connInfo.Done:
				// 根据关闭原因显示不同的日志
				if connInfo.CloseReason != "" {
					log.Printf("服务器连接正在关闭 (%s): %s", connInfo.CloseReason, clientAddr)
				} else {
					log.Printf("服务器连接正在关闭: %s", clientAddr)
				}
				return
			default:
				// 检查连接是否已关闭
				connInfo.CloseMutex.Lock()
				if connInfo.Closed {
					connInfo.CloseMutex.Unlock()
					return
				}
				connInfo.CloseMutex.Unlock()

				// 更新读取开始时间
				dataTransferStartTime := time.Now()

				// 每次读取前重置截止时间
				serverConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
				n, err := serverConn.Read(buffer)

				// 计算读取耗时
				dataTransferTime := time.Since(dataTransferStartTime)

				if err != nil {
					// 再次检查连接是否已关闭，避免记录已关闭连接的错误
					connInfo.CloseMutex.Lock()
					alreadyClosed := connInfo.Closed
					connInfo.CloseMutex.Unlock()

					if !alreadyClosed {
						if err != io.EOF {
							log.Printf("从 %s 的服务器读取时出错: %v", clientAddr, err)
						} else {
							log.Printf("服务器连接已关闭: %s", clientAddr)
						}
						// 设置服务器主动断开的关闭原因
						if err == io.EOF {
							connInfo.CloseReason = "服务器主动断开"
						} else {
							connInfo.CloseReason = fmt.Sprintf("服务器读取错误: %v", err)
						}
						safeCloseConnection()
					}
					return
				}

				// 如果读取用时较长，重置空闲计时器但不更新活动时间
				// 这避免了因为读取等待时间过长而触发空闲超时
				if dataTransferTime > time.Second {
					p.logVerbose("服务器 %s 的读取操作耗时 %.2f 秒", clientAddr, dataTransferTime.Seconds())
					if p.idleTimeout > 0 && connInfo.IdleTimer != nil {
						connInfo.IdleTimer.Reset(time.Duration(p.idleTimeout) * time.Second)
					}
				} else {
					// 仅在数据实际传输时更新活动时间
					p.updateActivity(connInfo)
				}

				// 检查连接是否已关闭
				connInfo.CloseMutex.Lock()
				if connInfo.Closed {
					connInfo.CloseMutex.Unlock()
					return
				}
				connInfo.CloseMutex.Unlock()

				// 开始写入的时间
				writeStartTime := time.Now()

				// 写入客户端
				_, err = clientConn.Write(buffer[:n])

				// 计算写入耗时
				writeTime := time.Since(writeStartTime)

				if err != nil {
					// 再次检查连接是否已关闭
					connInfo.CloseMutex.Lock()
					alreadyClosed := connInfo.Closed
					connInfo.CloseMutex.Unlock()

					if !alreadyClosed {
						log.Printf("写入客户端 %s 时出错: %v", clientAddr, err)
						connInfo.CloseReason = fmt.Sprintf("客户端写入错误: %v", err)
						safeCloseConnection()
					}
					return
				}

				// 如果写入用时较长，重置空闲计时器
				if writeTime > time.Second {
					p.logVerbose("写入客户端的操作耗时 %.2f 秒", writeTime.Seconds())
					if p.idleTimeout > 0 && connInfo.IdleTimer != nil {
						connInfo.IdleTimer.Reset(time.Duration(p.idleTimeout) * time.Second)
					}
				}
			}
		}
	}()

	// 等待两个复制操作完成或接收Done信号
	wgDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgDone)
	}()

	select {
	case <-wgDone:
		// 正常终止，可能是客户端或服务器主动断开
		p.logVerbose("数据转发已完成: %s", clientAddr)
	case <-connInfo.Done:
		// 其他原因导致的关闭（密码更改、空闲超时等）
		if connInfo.CloseReason != "" {
			log.Printf("正在关闭来自 %s 的连接，原因: %s", clientAddr, connInfo.CloseReason)
		} else {
			log.Printf("正在关闭来自 %s 的连接", clientAddr)
		}
	}
}

// performRFBAuthentication 与客户端执行RFB认证
func (p *VNCProxy) performRFBAuthentication(conn net.Conn) (bool, string, error) {
	// 在认证开始时捕获当前密码
	p.passwordMutex.RLock()
	currentPassword := p.password
	p.passwordMutex.RUnlock()

	// 步骤1：ProtocolVersion握手
	// 发送我们支持的版本
	if _, err := conn.Write([]byte(RFB_VERSION)); err != nil {
		return false, "", fmt.Errorf("发送协议版本失败: %v", err)
	}

	// 读取客户端的版本
	clientVersion := make([]byte, 12) // "RFB 003.008\n"是12字节
	if _, err := io.ReadFull(conn, clientVersion); err != nil {
		return false, "", fmt.Errorf("读取客户端版本失败: %v", err)
	}
	log.Printf("客户端版本: %s", string(clientVersion))

	// 步骤2：安全握手
	// 我们只支持VNC认证（类型2）
	securityTypes := []byte{1, SECURITY_TYPE_VNC} // 1种安全类型，类型2（VNC认证）
	if _, err := conn.Write(securityTypes); err != nil {
		return false, "", fmt.Errorf("发送安全类型失败: %v", err)
	}

	// 读取客户端选择的安全类型
	securityType := make([]byte, 1)
	if _, err := io.ReadFull(conn, securityType); err != nil {
		return false, "", fmt.Errorf("读取安全类型失败: %v", err)
	}

	if securityType[0] != SECURITY_TYPE_VNC {
		return false, "", fmt.Errorf("客户端选择了不支持的安全类型: %d", securityType[0])
	}

	// 步骤3：VNC认证
	// 生成随机挑战
	challenge := make([]byte, CHALLENGE_SIZE)
	// 在实际实现中，应该使用CSPRNG
	// 为简单起见，使用静态挑战（在生产中不推荐）
	for i := range challenge {
		challenge[i] = byte(i)
	}

	// 向客户端发送挑战
	if _, err := conn.Write(challenge); err != nil {
		return false, "", fmt.Errorf("发送挑战失败: %v", err)
	}

	// 读取客户端的响应
	response := make([]byte, CHALLENGE_SIZE)
	if _, err := io.ReadFull(conn, response); err != nil {
		return false, "", fmt.Errorf("读取认证响应失败: %v", err)
	}

	// 根据当前密码验证响应
	authenticated := p.verifyVNCAuth(challenge, response, currentPassword)

	// 发送认证结果
	var authResult uint32
	if authenticated {
		authResult = RFB_AUTH_SUCCESS
	} else {
		authResult = RFB_AUTH_FAILED
	}

	// 将认证结果写为大端uint32
	resultBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(resultBytes, authResult)
	if _, err := conn.Write(resultBytes); err != nil {
		return false, "", fmt.Errorf("发送认证结果失败: %v", err)
	}

	if !authenticated {
		// 如果认证失败，发送原因
		failureReason := "无效密码"
		reasonLen := make([]byte, 4)
		binary.BigEndian.PutUint32(reasonLen, uint32(len(failureReason)))
		conn.Write(reasonLen)
		conn.Write([]byte(failureReason))
		return false, "", nil
	}

	// 步骤4：ClientInit - 读取客户端的shared-flag
	sharedFlag := make([]byte, 1)
	if _, err := io.ReadFull(conn, sharedFlag); err != nil {
		return false, "", fmt.Errorf("读取shared标志失败: %v", err)
	}

	return true, currentPassword, nil
}

// performRFBHandshakeWithoutAuth 与客户端执行RFB握手，但不进行认证
func (p *VNCProxy) performRFBHandshakeWithoutAuth(conn net.Conn) error {
	// 步骤1：ProtocolVersion握手
	// 发送我们支持的版本
	if _, err := conn.Write([]byte(RFB_VERSION)); err != nil {
		return fmt.Errorf("发送协议版本失败: %v", err)
	}

	// 读取客户端的版本
	clientVersion := make([]byte, 12) // "RFB 003.008\n"是12字节
	if _, err := io.ReadFull(conn, clientVersion); err != nil {
		return fmt.Errorf("读取客户端版本失败: %v", err)
	}
	log.Printf("客户端版本: %s", string(clientVersion))

	// 步骤2：安全握手
	// 无密码模式下，我们使用无认证类型(SECURITY_TYPE_NONE)
	securityTypes := []byte{1, SECURITY_TYPE_NONE} // 1种安全类型，类型1（无认证）
	if _, err := conn.Write(securityTypes); err != nil {
		return fmt.Errorf("发送安全类型失败: %v", err)
	}

	// 读取客户端选择的安全类型
	securityType := make([]byte, 1)
	if _, err := io.ReadFull(conn, securityType); err != nil {
		return fmt.Errorf("读取安全类型失败: %v", err)
	}

	if securityType[0] != SECURITY_TYPE_NONE {
		return fmt.Errorf("客户端选择了不支持的安全类型: %d", securityType[0])
	}

	// 无认证模式下，不需要挑战-响应过程
	// 直接发送认证成功结果
	resultBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(resultBytes, RFB_AUTH_SUCCESS)
	if _, err := conn.Write(resultBytes); err != nil {
		return fmt.Errorf("发送认证结果失败: %v", err)
	}

	// 步骤4：ClientInit - 读取客户端的shared-flag
	sharedFlag := make([]byte, 1)
	if _, err := io.ReadFull(conn, sharedFlag); err != nil {
		return fmt.Errorf("读取shared标志失败: %v", err)
	}

	return nil
}

// relayInitialHandshake 处理与服务器的新RFB会话初始化
// 并正确中继客户端和服务器之间的初始化消息
func (p *VNCProxy) relayInitialHandshake(clientConn, serverConn net.Conn) error {
	_ = clientConn
	// 向服务器发送ProtocolVersion
	if _, err := serverConn.Write([]byte(RFB_VERSION)); err != nil {
		return fmt.Errorf("向服务器发送协议版本失败: %v", err)
	}

	// 读取服务器的协议版本
	serverVersion := make([]byte, 12)
	if _, err := io.ReadFull(serverConn, serverVersion); err != nil {
		return fmt.Errorf("读取服务器版本失败: %v", err)
	}
	log.Printf("服务器版本: %s", string(serverVersion))

	// 读取服务器的安全握手
	securityHeader := make([]byte, 1) // 安全类型数量
	if _, err := io.ReadFull(serverConn, securityHeader); err != nil {
		return fmt.Errorf("从服务器读取安全头失败: %v", err)
	}

	numSecTypes := int(securityHeader[0])
	securityTypes := make([]byte, numSecTypes)
	if _, err := io.ReadFull(serverConn, securityTypes); err != nil {
		return fmt.Errorf("从服务器读取安全类型失败: %v", err)
	}

	// 如果可用，选择SECURITY_TYPE_NONE (1)，否则选择第一种类型
	chosenType := securityTypes[0]
	for _, t := range securityTypes {
		if t == SECURITY_TYPE_NONE {
			chosenType = SECURITY_TYPE_NONE
			break
		}
	}

	// 向服务器发送选择的安全类型
	if _, err := serverConn.Write([]byte{chosenType}); err != nil {
		return fmt.Errorf("向服务器发送选择的安全类型失败: %v", err)
	}

	// 如果服务器需要认证，处理它
	if chosenType != SECURITY_TYPE_NONE {
		// 这是简化的 - 在实际实现中，您需要正确
		// 处理不同的认证类型。这里我们只假设简单的VNC认证。
		challenge := make([]byte, CHALLENGE_SIZE)
		if _, err := io.ReadFull(serverConn, challenge); err != nil {
			return fmt.Errorf("从服务器读取认证挑战失败: %v", err)
		}

		// 向服务器发送虚拟响应 - 这假设服务器不
		// 实际检查密码，这在实际场景中可能不是真的
		dummyResponse := make([]byte, CHALLENGE_SIZE)
		if _, err := serverConn.Write(dummyResponse); err != nil {
			return fmt.Errorf("向服务器发送认证响应失败: %v", err)
		}
	}

	// 从服务器读取认证结果
	authResult := make([]byte, 4)
	if _, err := io.ReadFull(serverConn, authResult); err != nil {
		return fmt.Errorf("从服务器读取认证结果失败: %v", err)
	}

	// 如果服务器认证失败
	if binary.BigEndian.Uint32(authResult) != 0 {
		// 读取失败原因长度
		reasonLen := make([]byte, 4)
		if _, err := io.ReadFull(serverConn, reasonLen); err != nil {
			return fmt.Errorf("读取失败原因长度失败: %v", err)
		}

		// 读取失败原因
		length := binary.BigEndian.Uint32(reasonLen)
		reason := make([]byte, length)
		if _, err := io.ReadFull(serverConn, reason); err != nil {
			return fmt.Errorf("读取失败原因失败: %v", err)
		}

		return fmt.Errorf("服务器认证失败: %s", string(reason))
	}

	// 从客户端向服务器转发ClientInit（shared标志）
	// 注意：在performRFBAuthentication和performRFBHandshakeWithoutAuth中已经读取了shared flag
	// 这里直接发送固定值"1"表示共享连接
	sharedFlag := []byte{1} // 使用1表示共享桌面连接
	if _, err := serverConn.Write(sharedFlag); err != nil {
		return fmt.Errorf("向服务器发送shared标志失败: %v", err)
	}

	// 此时，初始化完成，我们可以在双向中继客户端和服务器之间的数据
	return nil
}

// verifyVNCAuth 使用DES验证VNC认证响应
func (p *VNCProxy) verifyVNCAuth(challenge, response []byte, password string) bool {
	// VNC认证使用DES加密带密码的挑战
	// 密码被填充或截断为8字节
	var key [8]byte
	copy(key[:], []byte(password))

	// 对于VNC认证，密钥中的每个位都被翻转
	for i := range key {
		// 翻转位 - 在VNC认证中，它们反转位顺序
		key[i] = ((key[i] & 0x01) << 7) |
			((key[i] & 0x02) << 5) |
			((key[i] & 0x04) << 3) |
			((key[i] & 0x08) << 1) |
			((key[i] & 0x10) >> 1) |
			((key[i] & 0x20) >> 3) |
			((key[i] & 0x40) >> 5) |
			((key[i] & 0x80) >> 7)
	}

	// 将挑战分为两个块用于DES加密
	block, err := des.NewCipher(key[:])
	if err != nil {
		log.Printf("创建DES密码器时出错: %v", err)
		return false
	}

	// 加密两个8字节块的挑战
	expectedResponse := make([]byte, CHALLENGE_SIZE)
	block.Encrypt(expectedResponse[:8], challenge[:8])
	block.Encrypt(expectedResponse[8:], challenge[8:])

	// 比较预期响应与实际响应
	return bytes.Equal(expectedResponse, response)
}

// updateActivity 更新连接的最近活动时间并重置空闲计时器
func (p *VNCProxy) updateActivity(connInfo *ConnectionInfo) {
	// 更新最近活动时间
	now := time.Now()

	// 计算距离上次活动的时间
	idleTime := now.Sub(connInfo.LastActivity)
	p.logVerbose("客户端 %s 活动更新: 空闲时间 %.2f 秒", connInfo.ClientAddr, idleTime.Seconds())

	// 更新活动时间
	connInfo.LastActivity = now

	// 如果启用了空闲超时并且计时器已存在，重置计时器
	if p.idleTimeout > 0 && connInfo.IdleTimer != nil {
		connInfo.IdleTimer.Reset(time.Duration(p.idleTimeout) * time.Second)
		p.logVerbose("客户端 %s 的空闲计时器已重置为 %d 秒", connInfo.ClientAddr, p.idleTimeout)
	}
}

// setupIdleTimeout 为连接设置空闲超时
func (p *VNCProxy) setupIdleTimeout(connInfo *ConnectionInfo) {
	// 如果空闲超时被禁用，直接返回
	if p.idleTimeout <= 0 {
		return
	}

	log.Printf("为客户端 %s 设置空闲超时: %d秒", connInfo.ClientAddr, p.idleTimeout)

	// 创建空闲超时计时器
	connInfo.IdleTimer = time.AfterFunc(time.Duration(p.idleTimeout)*time.Second, func() {
		// 计算实际空闲时间
		idleTime := time.Since(connInfo.LastActivity)

		if idleTime >= time.Duration(p.idleTimeout)*time.Second {
			log.Printf("客户端 %s 已空闲 %.2f 秒，断开连接", connInfo.ClientAddr, idleTime.Seconds())

			// 设置关闭原因
			connInfo.CloseReason = fmt.Sprintf("空闲超时（%.1f分钟）", idleTime.Minutes())

			// 使用安全的方法关闭连接
			connInfo.SafeClose()

			// 注意：不需要显式关闭网络连接，这将在handleConnection的延迟函数中处理
		} else {
			// 如果连接在计时器触发前有活动，重置计时器
			newTimeout := time.Duration(p.idleTimeout)*time.Second - idleTime
			p.logVerbose("客户端 %s 最近有活动，重置空闲计时器为 %.1f 秒",
				connInfo.ClientAddr, newTimeout.Seconds())

			connInfo.IdleTimer.Reset(newTimeout)
		}
	})
}
