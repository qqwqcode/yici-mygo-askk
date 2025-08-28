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
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
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
	CacheSize           = 1000
	MaxCacheWorkers     = 10
	RateLimitDuration   = 15 * time.Second
	RateLimitSpeed      = 1024 // 1KB/s
)

// 全局配置变量
var (
	TargetURLs              []string // 改名为 TargetURLs，因为现在存储完整URL
	IgnoreSSLErrors         = true
	OnlyShowNon200Errors    = true
	EnableGRPC              = false
	EnableWebSocket         = false
	EnableH3QUIC            = true
	EnableRandomPath        = true
	EnableRandomQueryParams = true  // 新增：随机查询参数开关
	EnableRateLimit         = false
	EnableTrafficSimulation = false // 新增：流量仿真模式开关
	EnableFixedHeaders      = false // 新增：固定header模式开关
	MinTLSVersion           = tls.VersionTLS10
	MaxTLSVersion           = tls.VersionTLS13
	UseRandomMethod         = false
	GlobalCacheHeaders      = map[string]string{
		"Cache-Control": "no-cache, no-store, must-revalidate",
		"Pragma":        "no-cache",
		"Expires":       "0",
	}
	
	// 全局固定Cookie存储
	GlobalCookies      = make(map[string]string)
	GlobalFixedHeaders = make(map[string]string)
	cookieMutex        sync.RWMutex
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
	TotalRequests         int64
	TotalResponses        int64
	Non200Responses       int64
	FailedRequests        int64
	TotalResponseSize     int64
	HangingConnections    int64
	OneByteModeConns      int64
	SlowReceiveConns      int64
	GRPCRequests          int64
	WSRequests            int64
	RedirectsFollowed     int64 // 新增：跟随的跳转次数
	Handle403Count        int64 // 新增：处理的403次数
	TrafficSimRequests    int64 // 新增：流量仿真请求次数
	CookieUpdates         int64 // 新增：Cookie更新次数
	ErrorTypes            map[string]int64
	mu                    sync.RWMutex
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

// Chrome浏览器标识
var chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// Chrome标准请求头
var chromeHeaders = map[string]string{
	"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"Accept-Language":           "zh-CN,zh;q=0.9,en;q=0.8",
	"Accept-Encoding":           "gzip, deflate, br",
	"Cache-Control":            "no-cache",
	"Pragma":                   "no-cache",
	"Sec-Ch-Ua":                `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
	"Sec-Ch-Ua-Mobile":         "?0",
	"Sec-Ch-Ua-Platform":       `"Windows"`,
	"Sec-Fetch-Dest":           "document",
	"Sec-Fetch-Mode":           "navigate",
	"Sec-Fetch-Site":           "none",
	"Sec-Fetch-User":           "?1",
	"Upgrade-Insecure-Requests": "1",
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

// JS跳转检测正则表达式
var jsRedirectRegexes = []*regexp.Regexp{
	regexp.MustCompile(`window\.location\s*=\s*['"](.*?)['"]`),
	regexp.MustCompile(`window\.location\.href\s*=\s*['"](.*?)['"]`),
	regexp.MustCompile(`location\.replace\s*\(\s*['"](.*?)['"]\s*\)`),
	regexp.MustCompile(`document\.location\s*=\s*['"](.*?)['"]`),
	regexp.MustCompile(`<meta[^>]*http-equiv\s*=\s*['"]*refresh['"]*[^>]*content\s*=\s*['"]*\d+;\s*url\s*=\s*(.*?)['">]`),
}

// 加载目标URL
func loadTargetURLs() error {
	file, err := os.Open("dependency.txt")
	if err != nil {
		return fmt.Errorf("无法打开dependency.txt文件: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// 验证URL格式
			if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
				log.Printf("警告: 跳过无效URL格式: %s (应该以http://或https://开头)", line)
				continue
			}
			
			// 验证URL是否可解析
			if _, err := url.Parse(line); err != nil {
				log.Printf("警告: 跳过无法解析的URL: %s (%v)", line, err)
				continue
			}
			
			TargetURLs = append(TargetURLs, line)
		}
	}

	if len(TargetURLs) == 0 {
		return fmt.Errorf("dependency.txt文件中没有找到有效的URL")
	}

	return scanner.Err()
}

// 生成随机User-Agent
func generateRandomUserAgent() string {
	if EnableTrafficSimulation {
		return chromeUserAgent
	}
	
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

// 生成随机路径
func generateRandomPath() string {
	if !EnableRandomPath {
		return ""
	}
	
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	
	// 生成1-3级路径
	pathLevels := mathrand.Intn(3) + 1
	var pathParts []string
	
	for i := 0; i < pathLevels; i++ {
		partLength := mathrand.Intn(15) + 3 // 3-17字符
		part := make([]byte, partLength)
		for j := range part {
			part[j] = chars[mathrand.Intn(len(chars))]
		}
		pathParts = append(pathParts, string(part))
	}
	
	return strings.Join(pathParts, "/")
}

// 生成随机查询参数
func generateRandomQueryParams() string {
	if !EnableRandomQueryParams {
		return ""
	}
	
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	
	// 生成1-4个查询参数
	paramCount := mathrand.Intn(4) + 1
	var params []string
	
	for i := 0; i < paramCount; i++ {
		// 生成参数名
		keyLength := mathrand.Intn(8) + 3 // 3-10字符
		key := make([]byte, keyLength)
		for j := range key {
			key[j] = chars[mathrand.Intn(len(chars))]
		}
		
		// 生成参数值
		valueLength := mathrand.Intn(20) + 1 // 1-20字符
		value := make([]byte, valueLength)
		for j := range value {
			value[j] = chars[mathrand.Intn(len(chars))]
		}
		
		params = append(params, fmt.Sprintf("%s=%s", string(key), string(value)))
	}
	
	return strings.Join(params, "&")
}

// 生成随机URL
func generateRandomURL() string {
	baseURL := TargetURLs[mathrand.Intn(len(TargetURLs))]
	
	if !EnableRandomPath && !EnableRandomQueryParams {
		return baseURL
	}
	
	// 解析基础URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		// 如果解析失败，直接返回原URL
		return baseURL
	}
	
	// 处理随机路径
	if EnableRandomPath {
		randomPath := generateRandomPath()
		if randomPath != "" {
			// 在现有路径基础上添加随机路径
			if parsedURL.Path == "" || parsedURL.Path == "/" {
				parsedURL.Path = "/" + randomPath
			} else {
				// 去掉末尾的斜杠，然后添加新路径
				basePath := strings.TrimSuffix(parsedURL.Path, "/")
				parsedURL.Path = basePath + "/" + randomPath
			}
		}
	}
	
	// 处理随机查询参数
	if EnableRandomQueryParams && mathrand.Float32() < 0.7 { // 70%概率添加查询参数
		newParams := generateRandomQueryParams()
		if newParams != "" {
			existingQuery := parsedURL.Query()
			if len(existingQuery) > 0 {
				parsedURL.RawQuery = parsedURL.RawQuery + "&" + newParams
			} else {
				parsedURL.RawQuery = newParams
			}
		}
	}
	
	return parsedURL.String()
}

// 提取和保存Cookies
func extractAndSaveCookies(resp *http.Response) {
	if !EnableFixedHeaders {
		return
	}
	
	cookieMutex.Lock()
	defer cookieMutex.Unlock()
	
	cookies := resp.Cookies()
	if len(cookies) > 0 {
		var cookieStrings []string
		for _, cookie := range cookies {
			GlobalCookies[cookie.Name] = cookie.Value
			cookieStrings = append(cookieStrings, fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
		}
		
		if len(cookieStrings) > 0 {
			GlobalFixedHeaders["Cookie"] = strings.Join(cookieStrings, "; ")
			log.Printf("更新全局Cookie: %s", GlobalFixedHeaders["Cookie"])
		}
	}
}

// 构建Cookie字符串
func buildCookieString() string {
	if !EnableFixedHeaders {
		return ""
	}
	
	cookieMutex.RLock()
	defer cookieMutex.RUnlock()
	
	if cookieStr, exists := GlobalFixedHeaders["Cookie"]; exists {
		return cookieStr
	}
	
	if len(GlobalCookies) == 0 {
		return ""
	}
	
	var cookies []string
	for name, value := range GlobalCookies {
		cookies = append(cookies, fmt.Sprintf("%s=%s", name, value))
	}
	
	return strings.Join(cookies, "; ")
}

// 检测JS跳转
func detectJSRedirect(body string) string {
	for _, regex := range jsRedirectRegexes {
		matches := regex.FindStringSubmatch(body)
		if len(matches) > 1 {
			redirectURL := strings.TrimSpace(matches[1])
			// 清理URL中的引号和其他字符
			redirectURL = strings.Trim(redirectURL, `'"`)
			redirectURL = strings.TrimSuffix(redirectURL, `"`)
			redirectURL = strings.TrimSuffix(redirectURL, `'`)
			
			if redirectURL != "" && !strings.Contains(redirectURL, "javascript:") {
				return redirectURL
			}
		}
	}
	return ""
}

// 模拟鼠标滑动等待（处理403）
func simulateMouseMovementAndWait() {
	// 模拟用户在页面上的随机操作
	waitTime := time.Duration(8+mathrand.Intn(5)) * time.Second // 8-12秒随机等待
	log.Printf("检测到403，模拟用户操作，等待 %v 后重试...", waitTime)
	time.Sleep(waitTime)
}

// 生成随机请求头
func generateRandomHeaders() map[string]string {
	headers := make(map[string]string)
	
	if EnableTrafficSimulation {
		// 流量仿真模式：使用Chrome标准头
		for k, v := range chromeHeaders {
			headers[k] = v
		}
		headers["User-Agent"] = chromeUserAgent
		
		// 添加固定的Cookie（如果有）
		if cookieStr := buildCookieString(); cookieStr != "" {
			headers["Cookie"] = cookieStr
		}
		
	} else if EnableFixedHeaders {
		// 固定header模式
		for k, v := range GlobalFixedHeaders {
			headers[k] = v
		}
		
		// 如果没有User-Agent，生成一个
		if _, exists := headers["User-Agent"]; !exists {
			headers["User-Agent"] = generateRandomUserAgent()
		}
		
		// 添加固定的Cookie
		if cookieStr := buildCookieString(); cookieStr != "" {
			headers["Cookie"] = cookieStr
		}
		
	} else {
		// 原有的随机模式
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
	}
	
	return headers
}

// 初始化全局固定Headers（通过第一次Chrome请求）
func initializeGlobalHeaders() error {
	if !EnableFixedHeaders && !EnableTrafficSimulation {
		return nil
	}
	
	if len(TargetURLs) == 0 {
		return fmt.Errorf("没有可用的目标URL")
	}
	
	fmt.Println("正在通过Chrome请求初始化全局Headers和Cookies...")
	
	// 创建一个带Cookie Jar的客户端
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: IgnoreSSLErrors,
			},
		},
		Timeout: 30 * time.Second,
	}
	
	// 使用第一个URL进行初始化请求
	targetURL := TargetURLs[0]
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return fmt.Errorf("创建初始化请求失败: %v", err)
	}
	
	// 设置Chrome头部
	for k, v := range chromeHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", chromeUserAgent)
	
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("初始化请求失败，将使用默认配置: %v", err)
		return nil // 不返回错误，继续使用默认配置
	}
	defer resp.Body.Close()
	
	// 保存响应头中的有用信息
	if EnableFixedHeaders {
		cookieMutex.Lock()
		
		// 复制Chrome标准头作为基础
		for k, v := range chromeHeaders {
			GlobalFixedHeaders[k] = v
		}
		GlobalFixedHeaders["User-Agent"] = chromeUserAgent
		
		// 提取并保存Cookies
		extractAndSaveCookies(resp)
		
		cookieMutex.Unlock()
		
		fmt.Printf("全局Headers初始化完成，提取到 %d 个Cookie\n", len(GlobalCookies))
	}
	
	return nil
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
		
		if UseRandomMethod && !EnableTrafficSimulation {
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
	
	// 如果是固定header模式，更新Cookie
	if EnableFixedHeaders && len(GlobalCookies) > 0 {
		newHeaders := make(map[string]string)
		for k, v := range headers {
			newHeaders[k] = v
		}
		if cookieStr := buildCookieString(); cookieStr != "" {
			newHeaders["Cookie"] = cookieStr
		}
		headers = newHeaders
	}
	
	// 异步更新缓存项
	if mathrand.Float32() < 0.1 { // 10% 概率更新缓存项
		go func(idx int64) {
			cache.mu.Lock()
			cache.URLs[idx] = generateRandomURL()
			cache.Payloads[idx] = generateRandomPayload()
			cache.Headers[idx] = generateRandomHeaders()
			if UseRandomMethod && !EnableTrafficSimulation {
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

// 流量仿真模式的HTTP请求处理（支持跟随跳转和403处理）
func makeTrafficSimulationRequest(client *http.Client, method, initialURL string, payload []byte, headers map[string]string, stats *Stats, mode TestMode) {
	maxRedirects := 5
	currentURL := initialURL
	
	atomic.AddInt64(&stats.TrafficSimRequests, 1)
	
	for redirectCount := 0; redirectCount < maxRedirects; redirectCount++ {
		var req *http.Request
		var err error
		
		if method == "POST" || method == "PUT" || method == "PATCH" {
			req, err = http.NewRequest(method, currentURL, bytes.NewBuffer(payload))
			if err != nil {
				atomic.AddInt64(&stats.FailedRequests, 1)
				recordError(stats, "请求创建失败")
				return
			}
			req.Header.Set("Content-Type", "application/json")
		} else {
			req, err = http.NewRequest("GET", currentURL, nil) // 流量仿真主要用GET
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
		
		// 如果是跟随跳转，设置Referer
		if redirectCount > 0 {
			req.Header.Set("Referer", initialURL)
		}
		
		// 执行请求
		resp, err := client.Do(req)
		if err != nil {
			atomic.AddInt64(&stats.FailedRequests, 1)
			recordError(stats, "请求执行失败")
			if !OnlyShowNon200Errors {
				log.Printf("流量仿真请求失败 [%s %s]: %v", method, currentURL, err)
			}
			return
		}
		
		atomic.AddInt64(&stats.TotalRequests, 1)
		
		// 提取和保存新的Cookie
		extractAndSaveCookies(resp)
		if len(resp.Cookies()) > 0 {
			atomic.AddInt64(&stats.CookieUpdates, 1)
		}
		
		// 处理403状态码
		if resp.StatusCode == 403 {
			resp.Body.Close()
			atomic.AddInt64(&stats.Handle403Count, 1)
			atomic.AddInt64(&stats.Non200Responses, 1)
			recordError(stats, "HTTP_403")
			
			log.Printf("遇到403响应 [%s], 模拟用户行为后重试...", currentURL)
			simulateMouseMovementAndWait()
			
			// 重试当前URL，但不计入跳转次数
			redirectCount--
			continue
		}
		
		// 读取响应体
		var reader io.Reader = resp.Body
		if EnableRateLimit && mode == ModeNormal {
			reader = NewRateLimitedReader(reader)
		}
		
		var body []byte
		switch mode {
		case ModeOneByte:
			reader = &OneByteReader{reader: reader}
			body, _ = io.ReadAll(reader)
			atomic.AddInt64(&stats.OneByteModeConns, 1)
		case ModeSlowReceive:
			reader = &SlowReader{reader: reader}
			body, _ = io.ReadAll(reader)
			atomic.AddInt64(&stats.SlowReceiveConns, 1)
		case ModeHangUp:
			atomic.AddInt64(&stats.HangingConnections, 1)
			// 不读取响应，不关闭连接
			return
		default:
			body, err = io.ReadAll(reader)
			if err != nil {
				resp.Body.Close()
				atomic.AddInt64(&stats.FailedRequests, 1)
				recordError(stats, "响应读取失败")
				return
			}
		}
		
		resp.Body.Close()
		
		atomic.AddInt64(&stats.TotalResponseSize, int64(len(body)))
		
		// 检查HTTP跳转
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location != "" {
				// 解析跳转URL
				redirectURL, err := url.Parse(location)
				if err == nil {
					// 如果是相对URL，转换为绝对URL
					if !redirectURL.IsAbs() {
						baseURL, _ := url.Parse(currentURL)
						redirectURL = baseURL.ResolveReference(redirectURL)
					}
					
					currentURL = redirectURL.String()
					atomic.AddInt64(&stats.RedirectsFollowed, 1)
					log.Printf("跟随HTTP跳转: %s -> %s", req.URL.String(), currentURL)
					continue
				}
			}
		}
		
		// 检查JS跳转（仅在200响应时）
		if resp.StatusCode == 200 && len(body) > 0 {
			jsRedirectURL := detectJSRedirect(string(body))
			if jsRedirectURL != "" {
				// 解析JS跳转URL
				redirectURL, err := url.Parse(jsRedirectURL)
				if err == nil {
					// 如果是相对URL，转换为绝对URL
					if !redirectURL.IsAbs() {
						baseURL, _ := url.Parse(currentURL)
						redirectURL = baseURL.ResolveReference(redirectURL)
					}
					
					newURL := redirectURL.String()
					// 避免无限循环
					if newURL != currentURL {
						currentURL = newURL
						atomic.AddInt64(&stats.RedirectsFollowed, 1)
						log.Printf("跟随JS跳转: %s -> %s", req.URL.String(), currentURL)
						
						// JS跳转通常需要等待一下
						time.Sleep(time.Duration(1+mathrand.Intn(3)) * time.Second)
						continue
					}
				}
			}
		}
		
		// 处理最终响应
		if resp.StatusCode != 200 {
			atomic.AddInt64(&stats.Non200Responses, 1)
			recordError(stats, fmt.Sprintf("HTTP_%d", resp.StatusCode))
			if OnlyShowNon200Errors {
				log.Printf("流量仿真非200响应 [%s %s]: %d", method, currentURL, resp.StatusCode)
			}
		} else {
			atomic.AddInt64(&stats.TotalResponses, 1)
		}
		
		// 成功处理，退出循环
		break
	}
}

// 普通HTTP请求处理
func makeHTTPRequest(client *http.Client, method, url string, payload []byte, headers map[string]string, stats *Stats, mode TestMode) {
	// 如果启用了流量仿真模式，使用专门的处理函数
	if EnableTrafficSimulation {
		makeTrafficSimulationRequest(client, method, url, payload, headers, stats, mode)
		return
	}
	
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
	
	// 如果启用固定headers模式，提取Cookie
	if EnableFixedHeaders {
		extractAndSaveCookies(resp)
		if len(resp.Cookies()) > 0 {
			atomic.AddInt64(&stats.CookieUpdates, 1)
		}
	}
	
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
	
	// 如果是流量仿真模式，创建支持Cookie的客户端
	var jar http.CookieJar
	if EnableTrafficSimulation || EnableFixedHeaders {
		jar, _ = cookiejar.New(nil)
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		Jar:       jar,
		// 禁用自动跳转，我们手动处理
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if EnableTrafficSimulation {
				return http.ErrUseLastResponse // 阻止自动跳转
			}
			return nil // 允许自动跳转
		},
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
	
	// 加载目标URL
	if err := loadTargetURLs(); err != nil {
		log.Fatalf("加载目标URL失败: %v", err)
	}
	
	// 初始化全局Headers（如果启用）
	if err := initializeGlobalHeaders(); err != nil {
		log.Printf("初始化全局Headers失败: %v", err)
	}
	
	// 选择测试模式
	mode := ModeNormal // 可以修改为其他模式
	
	fmt.Printf("=== 增强型负载测试工具 ===\n")
	fmt.Printf("目标URL数量: %d\n", len(TargetURLs))
	fmt.Printf("示例URL:\n")
	for i, url := range TargetURLs {
		if i >= 3 { // 只显示前3个URL作为示例
			fmt.Printf("  ... 还有 %d 个URL\n", len(TargetURLs)-3)
			break
		}
		fmt.Printf("  %s\n", url)
	}
	
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
	if EnableRandomQueryParams {
		features = append(features, "随机查询参数")
	}
	if EnableRateLimit {
		features = append(features, "限速模式")
	}
	if UseRandomMethod {
		features = append(features, "随机HTTP方法")
	}
	if EnableTrafficSimulation {
		features = append(features, "流量仿真模式")
	}
	if EnableFixedHeaders {
		features = append(features, "固定Headers模式")
	}
	
	if len(features) == 0 {
		fmt.Println("仅HTTP")
	} else {
		fmt.Println(strings.Join(features, ", "))
	}
	
	// 显示Cookie信息（如果有）
	if EnableFixedHeaders && len(GlobalCookies) > 0 {
		fmt.Printf("初始Cookie数量: %d\n", len(GlobalCookies))
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
					
					// 流量仿真模式显示额外信息
					if EnableTrafficSimulation {
						redirects := atomic.LoadInt64(&stats.RedirectsFollowed)
						handle403 := atomic.LoadInt64(&stats.Handle403Count)
						fmt.Printf("进度: %d/%d (%.1f%%) - 速度: %.0f req/s - 错误: %d - 跳转: %d - 403处理: %d\n", 
							completed, TotalDownloads, progress, rate, errors, redirects, handle403)
					} else {
						fmt.Printf("进度: %d/%d (%.1f%%) - 速度: %.0f req/s - 错误: %d\n", 
							completed, TotalDownloads, progress, rate, errors)
					}
					
					// 显示Cookie更新信息
					if EnableFixedHeaders {
						cookieUpdates := atomic.LoadInt64(&stats.CookieUpdates)
						if cookieUpdates > 0 {
							fmt.Printf("Cookie更新次数: %d\n", cookieUpdates)
						}
					}
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
							if UseRandomMethod && !EnableTrafficSimulation {
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
	
	// 流量仿真模式特定统计
	if EnableTrafficSimulation {
		fmt.Printf("流量仿真请求: %d\n", atomic.LoadInt64(&stats.TrafficSimRequests))
		fmt.Printf("跟随跳转次数: %d\n", atomic.LoadInt64(&stats.RedirectsFollowed))
		fmt.Printf("403处理次数: %d\n", atomic.LoadInt64(&stats.Handle403Count))
		if atomic.LoadInt64(&stats.RedirectsFollowed) > 0 {
			avgRedirects := float64(atomic.LoadInt64(&stats.RedirectsFollowed)) / float64(atomic.LoadInt64(&stats.TrafficSimRequests))
			fmt.Printf("平均每个流量仿真请求跳转次数: %.2f\n", avgRedirects)
		}
	}
	
	// 固定Headers模式统计
	if EnableFixedHeaders {
		fmt.Printf("Cookie更新次数: %d\n", atomic.LoadInt64(&stats.CookieUpdates))
		cookieMutex.RLock()
		fmt.Printf("当前Cookie数量: %d\n", len(GlobalCookies))
		cookieMutex.RUnlock()
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
	
	// 流量仿真模式的额外评分说明
	if EnableTrafficSimulation {
		redirectRate := float64(atomic.LoadInt64(&stats.RedirectsFollowed)) / float64(atomic.LoadInt64(&stats.TotalRequests)) * 100
		handle403Rate := float64(atomic.LoadInt64(&stats.Handle403Count)) / float64(atomic.LoadInt64(&stats.TotalRequests)) * 100
		fmt.Printf("- 跳转处理能力: %.2f%% 的请求触发了跳转\n", redirectRate)
		fmt.Printf("- 反爬措施强度: %.2f%% 的请求遇到403\n", handle403Rate)
	}
	
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
	
	// 流量仿真模式的专门建议
	if EnableTrafficSimulation {
		handle403Count := atomic.LoadInt64(&stats.Handle403Count)
		if handle403Count > 0 {
			handle403Rate := float64(handle403Count) / float64(atomic.LoadInt64(&stats.TotalRequests)) * 100
			if handle403Rate > 20 {
				fmt.Printf("- 403响应过多(%.1f%%)，网站反爬措施较强，建议调整访问策略\n", handle403Rate)
			} else if handle403Rate > 5 {
				fmt.Printf("- 存在适量403响应(%.1f%%)，网站有一定反爬措施\n", handle403Rate)
			}
		}
		
		redirectCount := atomic.LoadInt64(&stats.RedirectsFollowed)
		if redirectCount > 0 {
			redirectRate := float64(redirectCount) / float64(atomic.LoadInt64(&stats.TotalRequests)) * 100
			fmt.Printf("- 跳转率为%.1f%%，网站具有良好的导航和重定向机制\n", redirectRate)
		}
		
		if len(GlobalCookies) > 0 {
			fmt.Printf("- 网站使用Cookie进行会话管理，测试过程中成功维护了会话状态\n")
		}
	}
	
	// 开关状态总结
	fmt.Printf("\n=== 功能开关状态 ===\n")
	fmt.Printf("随机路径: %v\n", EnableRandomPath)
	fmt.Printf("随机查询参数: %v\n", EnableRandomQueryParams)
	fmt.Printf("流量仿真模式: %v\n", EnableTrafficSimulation)
	fmt.Printf("固定Headers模式: %v\n", EnableFixedHeaders)
	fmt.Printf("限速模式: %v\n", EnableRateLimit)
	fmt.Printf("WebSocket支持: %v\n", EnableWebSocket)
	fmt.Printf("HTTP/3 QUIC支持: %v\n", EnableH3QUIC)
	fmt.Printf("gRPC支持: %v\n", EnableGRPC)
	fmt.Printf("随机HTTP方法: %v\n", UseRandomMethod)
	fmt.Printf("忽略SSL错误: %v\n", IgnoreSSLErrors)
	fmt.Printf("仅显示非200错误: %v\n", OnlyShowNon200Errors)
	
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
