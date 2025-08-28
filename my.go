package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// 配置常量
const (
	TotalDownloads       = 1000000
	NumConcurrentWorkers = 2000
	CacheSize           = 5000
	MaxCacheWorkers     = 100
	RateLimitDuration   = 15 * time.Second
	RateLimitSpeed      = 1024 // 1KB/s
)

// 全局配置变量
var (
	TargetDomains        []string
	IgnoreSSLErrors      = true
	OnlyShowNon200Errors = true
	EnableGRPC          = false
	EnableWebSocket     = false
	EnableH3QUIC        = false
	EnableRandomPath    = true
	EnableRateLimit     = true
	MinTLSVersion       = tls.VersionTLS10
	MaxTLSVersion       = tls.VersionTLS13
	UseRandomMethod     = false
	GlobalCacheHeaders  = map[string]string{
		"Cache-Control": "no-cache, no-store, must-revalidate",
		"Pragma":        "no-cache",
		"Expires":       "0",
	}
)

// 测试模式
type TestMode int

const (
	ModeNormal TestMode = iota // 正常模式：发送请求并接收响应
	ModeHangUp                 // 挂起模式：仅发送请求，不读取响应，保持连接
	ModeOneByte                // 仅接收1字节就断开
	ModeSlowReceive            // 极慢接收速度，直到服务器断开
)

// 协议类型
type ProtocolType int

const (
	ProtocolHTTP ProtocolType = iota
	ProtocolGRPC
	ProtocolWebSocket
)

// 统计信息结构体
type Stats struct {
	TotalRequests      int64
	TotalResponses     int64
	Non200Responses    int64
	FailedRequests     int64
	TotalResponseSize  int64
	HangingConnections int64
	OneByteModeConns   int64
	SlowReceiveConns   int64
	GRPCRequests       int64
	WSRequests         int64
	ErrorTypes         map[string]int64
	mu                 sync.RWMutex
}

// 请求缓存结构
type RequestCache struct {
	URLs     []string
	Payloads [][]byte
	Headers  []map[string]string
	Methods  []string
	mu       sync.RWMutex
	index    int64
}

// User-Agent 模板
var userAgentTemplates = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:%s) Gecko/20100101 Firefox/%s",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%s) Gecko/20100101 Firefox/%s",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
}

// HTTP方法列表
var httpMethods = []string{"GET", "POST", "PUT", "HEAD", "DELETE", "PATCH", "OPTIONS"}

// 加载目标域名
func loadTargetDomains() error {
	file, err := os.Open("dependency.txt")
	if err != nil {
		return fmt.Errorf("无法打开dependency.txt文件: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			TargetDomains = append(TargetDomains, domain)
		}
	}

	if len(TargetDomains) == 0 {
		return fmt.Errorf("dependency.txt文件中没有找到有效的域名")
	}

	return scanner.Err()
}

// 生成随机User-Agent
func generateRandomUserAgent() string {
	template := userAgentTemplates[mathrand.Intn(len(userAgentTemplates))]
	version := fmt.Sprintf("%d.0.%d.%d", 
		mathrand.Intn(41)+80,  // 80-120
		mathrand.Intn(9000)+1000, // 1000-9999
		mathrand.Intn(900)+100)   // 100-999
	
	if strings.Contains(template, "Firefox") {
		return fmt.Sprintf(template, version, version)
	}
	return fmt.Sprintf(template, version)
}

// 生成随机IP地址
func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		mathrand.Intn(256), mathrand.Intn(256), mathrand.Intn(256), mathrand.Intn(256))
}

// 生成随机负载数据
func generateRandomPayload() []byte {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	length := mathrand.Intn(901) + 100 // 100-1000
	data := make([]byte, length)
	for i := range data {
		data[i] = chars[mathrand.Intn(len(chars))]
	}
	
	payload := map[string]interface{}{
		"data": string(data),
		"timestamp": time.Now().Unix(),
		"random": mathrand.Int63(),
	}
	
	jsonData, _ := json.Marshal(payload)
	return jsonData
}

// 生成随机URL
func generateRandomURL() string {
	domain := TargetDomains[mathrand.Intn(len(TargetDomains))]
	
	if !EnableRandomPath {
		return domain
	}
	
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	pathLength := mathrand.Intn(20) + 5 // 5-24字符
	path := make([]byte, pathLength)
	for i := range path {
		path[i] = chars[mathrand.Intn(len(chars))]
	}
	
	// 添加随机查询参数
	queryParams := make([]string, mathrand.Intn(3)+1)
	for i := range queryParams {
		key := make([]byte, mathrand.Intn(8)+3)
		value := make([]byte, mathrand.Intn(15)+5)
		for j := range key {
			key[j] = chars[mathrand.Intn(len(chars))]
		}
		for j := range value {
			value[j] = chars[mathrand.Intn(len(chars))]
		}
		queryParams[i] = string(key) + "=" + string(value)
	}
	
	return fmt.Sprintf("%s/%s?%s", strings.TrimSuffix(domain, "/"), string(path), strings.Join(queryParams, "&"))
}

// 生成随机请求头
func generateRandomHeaders() map[string]string {
	headers := make(map[string]string)
	
	// 复制全局缓存头
	for k, v := range GlobalCacheHeaders {
		headers[k] = v
	}
	
	headers["User-Agent"] = generateRandomUserAgent()
	headers["X-Real-IP"] = generateRandomIP()
	headers["X-Forwarded-For"] = generateRandomIP()
	headers["Remote-Addr"] = generateRandomIP()
	headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	headers["Accept-Language"] = "en-US,en;q=0.5"
	headers["Accept-Encoding"] = "gzip, deflate"
	headers["Connection"] = "keep-alive"
	headers["Upgrade-Insecure-Requests"] = "1"
	
	// 随机添加一些额外的头
	extraHeaders := [][]string{
		{"X-Requested-With", "XMLHttpRequest"},
		{"Origin", "https://example.com"},
		{"Referer", "https://google.com/"},
		{"DNT", "1"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "cross-site"},
	}
	
	for _, header := range extraHeaders {
		if mathrand.Float32() < 0.3 { // 30% 概率添加
			headers[header[0]] = header[1]
		}
	}
	
	return headers
}

// 初始化请求缓存
func initRequestCache(cache *RequestCache) {
	fmt.Println("初始化请求缓存...")
	
	cache.URLs = make([]string, CacheSize)
	cache.Payloads = make([][]byte, CacheSize)
	cache.Headers = make([]map[string]string, CacheSize)
	cache.Methods = make([]string, CacheSize)
	
	for i := 0; i < CacheSize; i++ {
		cache.URLs[i] = generateRandomURL()
		cache.Payloads[i] = generateRandomPayload()
		cache.Headers[i] = generateRandomHeaders()
		
		if UseRandomMethod {
			cache.Methods[i] = httpMethods[mathrand.Intn(len(httpMethods))]
		} else {
			cache.Methods[i] = "GET"
		}
	}
	
	fmt.Printf("缓存初始化完成，预生成 %d 个请求\n", CacheSize)
}

// 从缓存获取请求数据
func getFromCache(cache *RequestCache) (string, []byte, map[string]string, string) {
	index := atomic.AddInt64(&cache.index, 1) % int64(CacheSize)
	
	cache.mu.RLock()
	url := cache.URLs[index]
	payload := cache.Payloads[index]
	headers := cache.Headers[index]
	method := cache.Methods[index]
	cache.mu.RUnlock()
	
	// 异步更新缓存项
	if mathrand.Float32() < 0.1 { // 10% 概率更新缓存项
		go func(idx int64) {
			cache.mu.Lock()
			cache.URLs[idx] = generateRandomURL()
			cache.Payloads[idx] = generateRandomPayload()
			cache.Headers[idx] = generateRandomHeaders()
			if UseRandomMethod {
				cache.Methods[idx] = httpMethods[mathrand.Intn(len(httpMethods))]
			}
			cache.mu.Unlock()
		}(index)
	}
	
	return url, payload, headers, method
}

// 限速读取器
type RateLimitedReader struct {
	reader    io.Reader
	startTime time.Time
	bytesRead int64
	enabled   bool
}

func NewRateLimitedReader(r io.Reader) *RateLimitedReader {
	return &RateLimitedReader{
		reader:    r,
		startTime: time.Now(),
		enabled:   EnableRateLimit,
	}
}

func (r *RateLimitedReader) Read(p []byte) (n int, err error) {
	if !r.enabled {
		return r.reader.Read(p)
	}
	
	elapsed := time.Since(r.startTime)
	if elapsed < RateLimitDuration {
		// 限速阶段
		allowedBytes := int64(float64(elapsed.Seconds()) * RateLimitSpeed)
		if r.bytesRead >= allowedBytes {
			// 需要等待
			sleepTime := time.Duration(float64(r.bytesRead-allowedBytes)/RateLimitSpeed) * time.Second
			time.Sleep(sleepTime)
		}
	}
	
	n, err = r.reader.Read(p)
	r.bytesRead += int64(n)
	return n, err
}

// 一字节读取器
type OneByteReader struct {
	reader io.Reader
	read   bool
}

func (r *OneByteReader) Read(p []byte) (n int, err error) {
	if r.read {
		return 0, io.EOF
	}
	
	if len(p) > 1 {
		p = p[:1]
	}
	
	n, err = r.reader.Read(p)
	if n > 0 {
		r.read = true
	}
	return n, err
}

// 慢速读取器
type SlowReader struct {
	reader    io.Reader
	lastRead  time.Time
	bytesRead int64
}

func (r *SlowReader) Read(p []byte) (n int, err error) {
	// 每次读取间隔至少1秒
	if !r.lastRead.IsZero() {
		elapsed := time.Since(r.lastRead)
		if elapsed < time.Second {
			time.Sleep(time.Second - elapsed)
		}
	}
	
	// 每次最多读取1字节
	if len(p) > 1 {
		p = p[:1]
	}
	
	n, err = r.reader.Read(p)
	r.lastRead = time.Now()
	r.bytesRead += int64(n)
	return n, err
}

// 记录错误类型
func recordError(stats *Stats, errType string) {
	stats.mu.Lock()
	if stats.ErrorTypes == nil {
		stats.ErrorTypes = make(map[string]int64)
	}
	stats.ErrorTypes[errType]++
	stats.mu.Unlock()
}

// WebSocket连接处理
func makeWebSocketRequest(url string, headers map[string]string, stats *Stats, mode TestMode) {
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: IgnoreSSLErrors,
			MinVersion:         uint16(MinTLSVersion),
			MaxVersion:         uint16(MaxTLSVersion),
		},
	}
	
	// 转换HTTP URL为WebSocket URL
	wsURL := strings.Replace(url, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		recordError(stats, "WebSocket连接失败")
		if !OnlyShowNon200Errors {
			log.Printf("WebSocket连接失败: %v", err)
		}
		return
	}
	defer conn.Close()
	
	atomic.AddInt64(&stats.WSRequests, 1)
	
	// 发送测试消息
	testMessage := map[string]interface{}{
		"type": "test",
		"data": "load test message",
		"timestamp": time.Now().Unix(),
	}
	
	if err := conn.WriteJSON(testMessage); err != nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		recordError(stats, "WebSocket发送失败")
		return
	}
	
	switch mode {
	case ModeOneByte:
		// 读取一个字节就断开
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, _, _ = conn.ReadMessage()
		atomic.AddInt64(&stats.OneByteModeConns, 1)
		
	case ModeSlowReceive:
		// 慢速读取直到超时
		for {
			conn.SetReadDeadline(time.Now().Add(time.Second))
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
			time.Sleep(time.Second) // 故意延迟
		}
		atomic.AddInt64(&stats.SlowReceiveConns, 1)
		
	case ModeHangUp:
		// 保持连接挂起
		atomic.AddInt64(&stats.HangingConnections, 1)
		time.Sleep(300 * time.Second)
		
	default:
		// 正常读取响应
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, message, err := conn.ReadMessage()
		if err == nil {
			atomic.AddInt64(&stats.TotalResponses, 1)
			atomic.AddInt64(&stats.TotalResponseSize, int64(len(message)))
		}
	}
}

// gRPC连接处理（简单示例）
func makeGRPCRequest(target string, stats *Stats) {
	conn, err := grpc.Dial(target, 
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithTimeout(30*time.Second))
	
	if err != nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		recordError(stats, "gRPC连接失败")
		if !OnlyShowNon200Errors {
			log.Printf("gRPC连接失败: %v", err)
		}
		return
	}
	defer conn.Close()
	
	// 创建上下文和metadata
	ctx := metadata.NewOutgoingContext(context.Background(), 
		metadata.Pairs("user-agent", generateRandomUserAgent()))
	
	// 这里需要根据实际的gRPC服务定义来调用
	// 由于没有具体的proto定义，这里只是示例
	atomic.AddInt64(&stats.GRPCRequests, 1)
	atomic.AddInt64(&stats.TotalRequests, 1)
	
	_ = ctx // 使用context避免编译警告
}

// HTTP请求处理
func makeHTTPRequest(client *http.Client, method, url string, payload []byte, headers map[string]string, stats *Stats, mode TestMode) {
	var req *http.Request
	var err error
	
	if method == "POST" || method == "PUT" || method == "PATCH" {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(payload))
		if err != nil {
			atomic.AddInt64(&stats.FailedRequests, 1)
			recordError(stats, "请求创建失败")
			return
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			atomic.AddInt64(&stats.FailedRequests, 1)
			recordError(stats, "请求创建失败")
			return
		}
	}
	
	// 设置所有请求头
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	
	// 执行请求
	resp, err := client.Do(req)
	if err != nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		recordError(stats, "请求执行失败")
		if !OnlyShowNon200Errors {
			log.Printf("请求失败 [%s %s]: %v", method, url, err)
		}
		return
	}
	
	atomic.AddInt64(&stats.TotalRequests, 1)
	
	switch mode {
	case ModeNormal:
		defer resp.Body.Close()
		
		var reader io.Reader = resp.Body
		if EnableRateLimit {
			reader = NewRateLimitedReader(reader)
		}
		
		body, err := io.ReadAll(reader)
		if err != nil {
			atomic.AddInt64(&stats.FailedRequests, 1)
			recordError(stats, "响应读取失败")
			return
		}
		
		atomic.AddInt64(&stats.TotalResponseSize, int64(len(body)))
		
		if resp.StatusCode != 200 {
			atomic.AddInt64(&stats.Non200Responses, 1)
			recordError(stats, fmt.Sprintf("HTTP_%d", resp.StatusCode))
			if OnlyShowNon200Errors {
				log.Printf("非200响应 [%s %s]: %d", method, url, resp.StatusCode)
			}
		} else {
			atomic.AddInt64(&stats.TotalResponses, 1)
		}
		
	case ModeOneByte:
		defer resp.Body.Close()
		reader := &OneByteReader{reader: resp.Body}
		io.ReadAll(reader)
		atomic.AddInt64(&stats.OneByteModeConns, 1)
		
	case ModeSlowReceive:
		defer resp.Body.Close()
		reader := &SlowReader{reader: resp.Body}
		io.ReadAll(reader)
		atomic.AddInt64(&stats.SlowReceiveConns, 1)
		
	case ModeHangUp:
		// 不读取响应，不关闭连接
		atomic.AddInt64(&stats.HangingConnections, 1)
		// 这里不defer close，让连接挂起
	}
}

// 工作协程
func worker(clients map[ProtocolType]interface{}, cache *RequestCache, stats *Stats, mode TestMode, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for i := 0; i < TotalDownloads/NumConcurrentWorkers; i++ {
		url, payload, headers, method := getFromCache(cache)
		
		// 根据配置选择协议
		if EnableWebSocket && mathrand.Float32() < 0.3 {
			makeWebSocketRequest(url, headers, stats, mode)
		} else {
			// HTTP/HTTP3请求
			var client *http.Client
			if EnableH3QUIC && mathrand.Float32() < 0.5 {
				client = clients[ProtocolHTTP].(*http.Client) // HTTP3 client
			} else {
				client = clients[ProtocolHTTP].(*http.Client) // Regular HTTP client
			}
			makeHTTPRequest(client, method, url, payload, headers, stats, mode)
		}
		
		// 小延迟避免过度压力
		time.Sleep(time.Millisecond * time.Duration(mathrand.Intn(10)))
	}
}

// 创建HTTP客户端
func createHTTPClient(mode TestMode, useHTTP3 bool) *http.Client {
	var transport http.RoundTripper
	
	if useHTTP3 && EnableH3QUIC {
		transport = &http3.RoundTripper{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: IgnoreSSLErrors,
				MinVersion:         uint16(MinTLSVersion),
				MaxVersion:         uint16(MaxTLSVersion),
			},
		}
	} else {
		transport = &http.Transport{
			MaxIdleConns:        10000,
			MaxIdleConnsPerHost: 2000,
			MaxConnsPerHost:     5000,
			IdleConnTimeout:     300 * time.Second,
			DisableKeepAlives:   mode == ModeHangUp,
			DisableCompression:  true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: IgnoreSSLErrors,
				MinVersion:         uint16(MinTLSVersion),
				MaxVersion:         uint16(MaxTLSVersion),
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, network, addr)
			},
		}
	}
	
	var timeout time.Duration
	switch mode {
	case ModeHangUp, ModeSlowReceive:
		timeout = 300 * time.Second
	case ModeOneByte:
		timeout = 5 * time.Second
	default:
		timeout = 30 * time.Second
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// 计算网站评分
func calculateWebsiteScore(stats *Stats, elapsed time.Duration) (score float64, rating string) {
	totalRequests := float64(atomic.LoadInt64(&stats.TotalRequests))
	successRate := float64(atomic.LoadInt64(&stats.TotalResponses)) / totalRequests
	errorRate := float64(atomic.LoadInt64(&stats.FailedRequests) + atomic.LoadInt64(&stats.Non200Responses)) / totalRequests
	avgRate := totalRequests / elapsed.Seconds()
	
	// 基础分数 (100分制)
	score = 100.0
	
	// 根据成功率扣分 (最多扣50分)
	score -= (1.0 - successRate) * 50
	
	// 根据错误率扣分 (最多扣30分)
	score -= errorRate * 30
	
	// 根据响应速度给分 (速度低于100 req/s扣分)
	if avgRate < 100 {
		score -= (100 - avgRate) * 0.2
	}
	
	// 确保分数在0-100范围内
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	
	// 评级
	switch {
	case score >= 90:
		rating = "优秀 (A+)"
	case score >= 80:
		rating = "良好 (A)"
	case score >= 70:
		rating = "一般 (B)"
	case score >= 60:
		rating = "较差 (C)"
	case score >= 40:
		rating = "很差 (D)"
	default:
		rating = "极差 (F)"
	}
	
	return score, rating
}

func main() {
	// 初始化随机种子
	mathrand.Seed(time.Now().UnixNano())
	
	// 加载目标域名
	if err := loadTargetDomains(); err != nil {
		log.Fatalf("加载目标域名失败: %v", err)
	}
	
	// 选择测试模式
	mode := ModeNormal // 可以修改为其他模式
	
	fmt.Printf("=== 增强型负载测试工具 ===\n")
	fmt.Printf("目标域名数量: %d\n", len(TargetDomains))
	fmt.Printf("测试模式: %s\n", func() string {
		switch mode {
		case ModeHangUp:
			return "挂起模式 (仅发送请求，不接收响应)"
		case ModeOneByte:
			return "一字节模式 (仅接收1字节就断开)"
		case ModeSlowReceive:
			return "慢接收模式 (极慢接收速度)"
		default:
			return "正常模式 (发送请求并接收响应)"
		}
	}())
	fmt.Printf("总请求数: %d\n", TotalDownloads)
	fmt.Printf("并发数: %d\n", NumConcurrentWorkers)
	fmt.Printf("启用功能: ")
	
	features := []string{}
	if EnableGRPC {
		features = append(features, "gRPC")
	}
	if EnableWebSocket {
		features = append(features, "WebSocket")
	}
	if EnableH3QUIC {
		features = append(features, "HTTP/3 QUIC")
	}
	if EnableRandomPath {
		features = append(features, "随机路径")
	}
	if EnableRateLimit {
		features = append(features, "限速模式")
	}
	if UseRandomMethod {
		features = append(features, "随机HTTP方法")
	}
	
	if len(features) == 0 {
		fmt.Println("仅HTTP")
	} else {
		fmt.Println(strings.Join(features, ", "))
	}
	
	// 初始化统计
	stats := &Stats{
		ErrorTypes: make(map[string]int64),
	}
	
	// 初始化请求缓存
	cache := &RequestCache{}
	initRequestCache(cache)
	
	// 创建各协议客户端
	clients := make(map[ProtocolType]interface{})
	clients[ProtocolHTTP] = createHTTPClient(mode, false)
	if EnableH3QUIC {
		// HTTP/3客户端将在worker中动态选择
	}
	
	
	// 启动工作协程
	var wg sync.WaitGroup
	for i := 0; i < NumConcurrentWorkers; i++ {
		wg.Add(1)
		go worker(clients, cache, stats, mode, &wg)
	}
	
	// 记录开始时间
	startTime := time.Now()
	
	// 启动进度监控
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				completed := atomic.LoadInt64(&stats.TotalRequests)
				elapsed := time.Since(startTime)
				rate := float64(completed) / elapsed.Seconds()
				
				progress := float64(completed) / float64(TotalDownloads) * 100
				
				switch mode {
				case ModeHangUp:
					hanging := atomic.LoadInt64(&stats.HangingConnections)
					fmt.Printf("进度: %d/%d (%.1f%%) - 速度: %.0f req/s - 挂起连接: %d\n", 
						completed, TotalDownloads, progress, rate, hanging)
				case ModeOneByte:
					oneByte := atomic.LoadInt64(&stats.OneByteModeConns)
					fmt.Printf("进度: %d/%d (%.1f%%) - 速度: %.0f req/s - 一字节连接: %d\n", 
						completed, TotalDownloads, progress, rate, oneByte)
				case ModeSlowReceive:
					slow := atomic.LoadInt64(&stats.SlowReceiveConns)
					fmt.Printf("进度: %d/%d (%.1f%%) - 速度: %.0f req/s - 慢接收连接: %d\n", 
						completed, TotalDownloads, progress, rate, slow)
				default:
					errors := atomic.LoadInt64(&stats.FailedRequests) + atomic.LoadInt64(&stats.Non200Responses)
					fmt.Printf("进度: %d/%d (%.1f%%) - 速度: %.0f req/s - 错误: %d\n", 
						completed, TotalDownloads, progress, rate, errors)
				}
			}
		}
	}()
	
	// 启动缓存预热协程
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// 预热下一批缓存
				if mathrand.Float32() < 0.1 { // 10% 概率预热缓存
					go func() {
						for i := 0; i < 100; i++ {
							index := mathrand.Intn(CacheSize)
							cache.mu.Lock()
							cache.URLs[index] = generateRandomURL()
							cache.Payloads[index] = generateRandomPayload()
							cache.Headers[index] = generateRandomHeaders()
							if UseRandomMethod {
								cache.Methods[index] = httpMethods[mathrand.Intn(len(httpMethods))]
							}
							cache.mu.Unlock()
						}
					}()
				}
			}
		}
	}()
	
	// 启动错误监控协程
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if OnlyShowNon200Errors {
					stats.mu.RLock()
					if len(stats.ErrorTypes) > 0 {
						fmt.Printf("=== 错误统计 ===\n")
						for errType, count := range stats.ErrorTypes {
							fmt.Printf("%s: %d 次\n", errType, count)
						}
						fmt.Println("================")
					}
					stats.mu.RUnlock()
				}
			}
		}
	}()
	
	// 等待所有工作完成
	wg.Wait()
	cancel()
	
	// 计算总用时
	elapsed := time.Since(startTime)
	
	// 输出统计结果
	totalTrafficGB := float64(atomic.LoadInt64(&stats.TotalResponseSize)) / (1024 * 1024 * 1024)
	avgRate := float64(atomic.LoadInt64(&stats.TotalRequests)) / elapsed.Seconds()
	successRate := float64(atomic.LoadInt64(&stats.TotalResponses)) / float64(atomic.LoadInt64(&stats.TotalRequests)) * 100
	
	fmt.Printf("\n=== 测试完成 ===\n")
	fmt.Printf("测试模式: %s\n", func() string {
		switch mode {
		case ModeHangUp:
			return "挂起模式"
		case ModeOneByte:
			return "一字节模式"
		case ModeSlowReceive:
			return "慢接收模式"
		default:
			return "正常模式"
		}
	}())
	fmt.Printf("总耗时: %v\n", elapsed)
	fmt.Printf("平均速度: %.0f req/s\n", avgRate)
	fmt.Printf("总请求次数: %d\n", atomic.LoadInt64(&stats.TotalRequests))
	fmt.Printf("成功率: %.2f%%\n", successRate)
	
	// 协议统计
	httpReqs := atomic.LoadInt64(&stats.TotalRequests) - atomic.LoadInt64(&stats.GRPCRequests) - atomic.LoadInt64(&stats.WSRequests)
	if httpReqs > 0 {
		fmt.Printf("HTTP请求: %d\n", httpReqs)
	}
	if atomic.LoadInt64(&stats.GRPCRequests) > 0 {
		fmt.Printf("gRPC请求: %d\n", atomic.LoadInt64(&stats.GRPCRequests))
	}
	if atomic.LoadInt64(&stats.WSRequests) > 0 {
		fmt.Printf("WebSocket请求: %d\n", atomic.LoadInt64(&stats.WSRequests))
	}
	
	// 模式特定统计
	switch mode {
	case ModeHangUp:
		fmt.Printf("挂起连接数: %d\n", atomic.LoadInt64(&stats.HangingConnections))
		fmt.Printf("注意: 挂起的连接将保持打开状态，直到程序退出或服务器关闭连接\n")
	case ModeOneByte:
		fmt.Printf("一字节连接数: %d\n", atomic.LoadInt64(&stats.OneByteModeConns))
	case ModeSlowReceive:
		fmt.Printf("慢接收连接数: %d\n", atomic.LoadInt64(&stats.SlowReceiveConns))
	default:
		fmt.Printf("成功响应次数: %d\n", atomic.LoadInt64(&stats.TotalResponses))
		fmt.Printf("非200响应次数: %d\n", atomic.LoadInt64(&stats.Non200Responses))
		fmt.Printf("总响应流量: %.2f GB\n", totalTrafficGB)
	}
	
	fmt.Printf("请求异常次数: %d\n", atomic.LoadInt64(&stats.FailedRequests))
	
	// 详细错误统计
	stats.mu.RLock()
	if len(stats.ErrorTypes) > 0 {
		fmt.Printf("\n=== 错误类型统计 ===\n")
		for errType, count := range stats.ErrorTypes {
			percentage := float64(count) / float64(atomic.LoadInt64(&stats.TotalRequests)) * 100
			fmt.Printf("%s: %d 次 (%.2f%%)\n", errType, count, percentage)
		}
	}
	stats.mu.RUnlock()
	
	// 网站素质评分
	score, rating := calculateWebsiteScore(stats, elapsed)
	fmt.Printf("\n=== 网站素质评分 ===\n")
	fmt.Printf("综合评分: %.1f/100\n", score)
	fmt.Printf("评级: %s\n", rating)
	
	// 评分详情
	fmt.Printf("\n评分依据:\n")
	fmt.Printf("- 成功率: %.2f%% (影响权重: 50%%)\n", successRate)
	errorRate := float64(atomic.LoadInt64(&stats.FailedRequests)+atomic.LoadInt64(&stats.Non200Responses)) / float64(atomic.LoadInt64(&stats.TotalRequests)) * 100
	fmt.Printf("- 错误率: %.2f%% (影响权重: 30%%)\n", errorRate)
	fmt.Printf("- 响应速度: %.0f req/s (影响权重: 20%%)\n", avgRate)
	
	if score >= 80 {
		fmt.Printf("总结: 该网站在高负载下表现优秀，具有良好的稳定性和性能。\n")
	} else if score >= 60 {
		fmt.Printf("总结: 该网站在高负载下表现一般，可能需要优化服务器配置或网络架构。\n")
	} else {
		fmt.Printf("总结: 该网站在高负载下表现较差，建议进行全面的性能优化。\n")
	}
	
	// 性能建议
	fmt.Printf("\n=== 性能建议 ===\n")
	if errorRate > 10 {
		fmt.Printf("- 错误率过高，建议检查服务器日志和错误处理机制\n")
	}
	if avgRate < 100 {
		fmt.Printf("- 响应速度较慢，建议优化服务器性能或增加带宽\n")
	}
	if atomic.LoadInt64(&stats.Non200Responses) > 0 {
		fmt.Printf("- 存在非200响应，建议检查API接口和路由配置\n")
	}
	if successRate < 95 {
		fmt.Printf("- 成功率偏低，建议增强服务器稳定性和容错能力\n")
	}
	
	fmt.Printf("依赖下载完成\n")
	
	if mode == ModeHangUp {
		fmt.Printf("程序将保持运行以维持挂起的连接，按 Ctrl+C 退出...\n")
		// 保持程序运行，维持挂起的连接
		select {} // 永久阻塞
	} else if mode == ModeSlowReceive {
		fmt.Printf("慢接收连接可能仍在运行，按 Ctrl+C 强制退出...\n")
		time.Sleep(5 * time.Second) // 给慢连接一点时间自然结束
	}
}
