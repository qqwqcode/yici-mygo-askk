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
	"math"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime"
	"sort"
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

// ===================================================================================
// --- 模式配置区域 (Mode Configuration Section) ---
// ===================================================================================

const SelectedTestMode = ModeNormal

// --- 优化的性能参数 ---
const (
	TotalDownloads       = 3000000               // 降低默认请求数以提高稳定性
	NumConcurrentWorkers = 10000                 // 优化并发数
	CacheSize            = 20000                // 增大缓存以减少重复生成
	RateLimitDuration    = 15 * time.Second
	RateLimitSpeed       = 2048                // 提高限速速度到2MB/s
	MaxIdleConns         = 20000                // 增加连接池
	MaxIdleConnsPerHost  = 20000
	IdleConnTimeout      = 60 * time.Second    // 延长空闲超时
	RequestTimeout       = 45 * time.Second    // 延长请求超时
	KeepAliveTimeout     = 60 * time.Second
	TLSHandshakeTimeout  = 15 * time.Second
	ResponseHeaderTimeout = 15 * time.Second
	StatsUpdateInterval  = 3 * time.Second     // 更频繁的统计更新
)

// --- 优化的功能开关 ---
var (
	EnableFixedHeaders        = false
	EnableWebSocket           = false  // 默认启用WebSocket
	EnableGRPC                = false
	EnableHTTP3               = true
	EnableRandomPath          = true
	EnableRandomQueryParams   = true  // 默认启用随机参数
	UseRandomMethod           = false  // 默认启用随机方法
	EnableMultipartFormData   = true  // 默认启用多部分数据
	EnableChunkedTransfer     = true  // 默认启用分块传输

	IgnoreSSLErrors                 = true
	HTTPVersions                    = "h3"
	MinTLSVersion                   = tls.VersionTLS10
	MaxTLSVersion                   = tls.VersionTLS13
	ForceNewTLSSessionPerConnection = true
	EnableSharedTLSSessionCache     = false

	EnableRateLimit       = false
	EnableConnectionReuse = true
	EnableCompression     = true
	EnableKeepAlive       = true

	EnableSlowloris       = false
	EnableSlowPost        = false
	EnableRandomUserAgent = true

	OnlyShowNon200Errors = true
	EnableVerboseLogging = true
	EnableProgressBar    = true
	
	// 新增计分系统开关
	EnableScoring = true // 启用计分系统
)

// ===================================================================================
// --- 计分系统 (Scoring System) ---
// ===================================================================================

type ScoreCard struct {
	// 基础性能指标 (40分)
	QPSScore          float64 // QPS得分 (20分)
	SuccessRateScore  float64 // 成功率得分 (10分)
	ResponseTimeScore float64 // 响应时间得分 (10分)
	
	// 稳定性指标 (30分)
	ErrorRateScore    float64 // 错误率得分 (15分)
	TimeoutScore      float64 // 超时处理得分 (15分)
	
	// 协议支持 (20分)
	ProtocolScore     float64 // 多协议支持得分 (20分)
	
	// 资源利用 (10分)
	ResourceScore     float64 // 资源利用效率得分 (10分)
	
	// 总分
	TotalScore        float64
	Grade             string  // 等级评价
}

// 计算QPS得分 (满分20分)
func calculateQPSScore(qps float64) float64 {
	// 基准: 1000 QPS = 10分, 2000 QPS = 15分, 5000+ QPS = 20分
	if qps >= 5000 {
		return 20.0
	} else if qps >= 2000 {
		return 15.0 + (qps-2000)/3000*5.0
	} else if qps >= 1000 {
		return 10.0 + (qps-1000)/1000*5.0
	} else if qps >= 500 {
		return 5.0 + (qps-500)/500*5.0
	} else {
		return math.Max(0, qps/500*5.0)
	}
}

// 计算成功率得分 (满分10分)
func calculateSuccessRateScore(successRate float64) float64 {
	if successRate >= 99.5 {
		return 10.0
	} else if successRate >= 95.0 {
		return 7.0 + (successRate-95.0)/4.5*3.0
	} else if successRate >= 90.0 {
		return 4.0 + (successRate-90.0)/5.0*3.0
	} else {
		return math.Max(0, successRate/90.0*4.0)
	}
}

// 计算响应时间得分 (满分10分)
func calculateResponseTimeScore(avgResponseTime time.Duration) float64 {
	ms := float64(avgResponseTime.Nanoseconds()) / 1e6
	if ms <= 100 {
		return 10.0
	} else if ms <= 500 {
		return 8.0 + (500-ms)/400*2.0
	} else if ms <= 1000 {
		return 5.0 + (1000-ms)/500*3.0
	} else if ms <= 3000 {
		return 2.0 + (3000-ms)/2000*3.0
	} else {
		return math.Max(0, 2.0-(ms-3000)/2000)
	}
}

// 计算错误率得分 (满分15分)
func calculateErrorRateScore(errorRate float64) float64 {
	if errorRate <= 0.5 {
		return 15.0
	} else if errorRate <= 2.0 {
		return 12.0 + (2.0-errorRate)/1.5*3.0
	} else if errorRate <= 5.0 {
		return 8.0 + (5.0-errorRate)/3.0*4.0
	} else if errorRate <= 10.0 {
		return 4.0 + (10.0-errorRate)/5.0*4.0
	} else {
		return math.Max(0, 4.0-errorRate/10.0*4.0)
	}
}

// 计算协议支持得分 (满分20分)
func calculateProtocolScore(stats *Stats) float64 {
	score := 8.0 // HTTP基础分
	
	if atomic.LoadInt64(&stats.WSRequests) > 0 {
		score += 4.0 // WebSocket支持
	}
	if atomic.LoadInt64(&stats.GRPCRequests) > 0 {
		score += 4.0 // gRPC支持
	}
	if atomic.LoadInt64(&stats.HTTP3Requests) > 0 {
		score += 4.0 // HTTP/3支持
	}
	
	return score
}

// 计算资源利用得分 (满分10分)
func calculateResourceScore(memUsageMB float64, goroutines int) float64 {
	// 内存使用评分 (5分)
	memScore := 5.0
	if memUsageMB > 1000 {
		memScore = math.Max(0, 5.0-(memUsageMB-1000)/1000*2.0)
	} else if memUsageMB > 500 {
		memScore = 4.0 + (1000-memUsageMB)/500*1.0
	}
	
	// 协程管理评分 (5分)
	goroutineScore := 5.0
	expectedGoroutines := NumConcurrentWorkers + 50 // 允许一些额外协程
	if goroutines > expectedGoroutines*2 {
		goroutineScore = math.Max(0, 5.0-float64(goroutines-expectedGoroutines)/float64(expectedGoroutines))
	}
	
	return memScore + goroutineScore
}

// 计算综合评分
func calculateScore(stats *Stats, totalDuration time.Duration, memUsageMB float64, goroutines int) *ScoreCard {
	scoreCard := &ScoreCard{}
	
	totalReq := atomic.LoadInt64(&stats.TotalRequests)
	totalResp := atomic.LoadInt64(&stats.TotalResponses)
	totalFailed := atomic.LoadInt64(&stats.FailedRequests)
	
	if totalReq == 0 {
		return scoreCard
	}
	
	// 计算基础指标
	qps := float64(totalReq) / totalDuration.Seconds()
	successRate := float64(totalResp) / float64(totalReq) * 100
	errorRate := float64(totalFailed) / float64(totalReq) * 100
	
	// 计算平均响应时间
	var avgResponseTime time.Duration
	stats.mu.RLock()
	if len(stats.ResponseTimes) > 0 {
		var total time.Duration
		for _, rt := range stats.ResponseTimes {
			total += rt
		}
		avgResponseTime = total / time.Duration(len(stats.ResponseTimes))
	}
	stats.mu.RUnlock()
	
	// 计算各项得分
	scoreCard.QPSScore = calculateQPSScore(qps)
	scoreCard.SuccessRateScore = calculateSuccessRateScore(successRate)
	scoreCard.ResponseTimeScore = calculateResponseTimeScore(avgResponseTime)
	scoreCard.ErrorRateScore = calculateErrorRateScore(errorRate)
	scoreCard.TimeoutScore = 15.0 // 基础分，根据超时情况扣分
	scoreCard.ProtocolScore = calculateProtocolScore(stats)
	scoreCard.ResourceScore = calculateResourceScore(memUsageMB, goroutines)
	
	// 计算总分
	scoreCard.TotalScore = scoreCard.QPSScore + scoreCard.SuccessRateScore + 
		scoreCard.ResponseTimeScore + scoreCard.ErrorRateScore + 
		scoreCard.TimeoutScore + scoreCard.ProtocolScore + scoreCard.ResourceScore
	
	// 确定等级
	if scoreCard.TotalScore >= 90 {
		scoreCard.Grade = "S级 (优秀)"
	} else if scoreCard.TotalScore >= 80 {
		scoreCard.Grade = "A级 (良好)"
	} else if scoreCard.TotalScore >= 70 {
		scoreCard.Grade = "B级 (中等)"
	} else if scoreCard.TotalScore >= 60 {
		scoreCard.Grade = "C级 (及格)"
	} else {
		scoreCard.Grade = "D级 (需要优化)"
	}
	
	return scoreCard
}

// 显示评分报告
func printScoreReport(scoreCard *ScoreCard, stats *Stats, totalDuration time.Duration) {
	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Printf("                    流量测试评分报告\n")
	fmt.Printf(strings.Repeat("=", 60) + "\n")
	
	totalReq := atomic.LoadInt64(&stats.TotalRequests)
	totalResp := atomic.LoadInt64(&stats.TotalResponses)
	qps := float64(totalReq) / totalDuration.Seconds()
	successRate := float64(totalResp) / float64(totalReq) * 100
	
	fmt.Printf("📊 基础性能指标 (40分)\n")
	fmt.Printf("  ┣━ QPS性能      : %.2f/20.0 分 (实际QPS: %.1f)\n", scoreCard.QPSScore, qps)
	fmt.Printf("  ┣━ 成功率       : %.2f/10.0 分 (实际成功率: %.1f%%)\n", scoreCard.SuccessRateScore, successRate)
	fmt.Printf("  ┗━ 响应时间     : %.2f/10.0 分\n", scoreCard.ResponseTimeScore)
	
	fmt.Printf("\n🛡️  稳定性指标 (30分)\n")
	fmt.Printf("  ┣━ 错误处理     : %.2f/15.0 分\n", scoreCard.ErrorRateScore)
	fmt.Printf("  ┗━ 超时控制     : %.2f/15.0 分\n", scoreCard.TimeoutScore)
	
	fmt.Printf("\n🌐 协议支持 (20分)\n")
	fmt.Printf("  ┗━ 多协议能力   : %.2f/20.0 分\n", scoreCard.ProtocolScore)
	
	fmt.Printf("\n💾 资源利用 (10分)\n")
	fmt.Printf("  ┗━ 资源效率     : %.2f/10.0 分\n", scoreCard.ResourceScore)
	
	fmt.Printf("\n" + strings.Repeat("-", 60) + "\n")
	fmt.Printf("🏆 总分: %.2f/100.0 分\n", scoreCard.TotalScore)
	fmt.Printf("🎖️  等级: %s\n", scoreCard.Grade)
	fmt.Printf(strings.Repeat("=", 60) + "\n")
	
	// 性能建议
	printPerformanceSuggestions(scoreCard, qps, successRate)
}

// 性能优化建议
func printPerformanceSuggestions(scoreCard *ScoreCard, qps, successRate float64) {
	fmt.Printf("\n💡 性能优化建议:\n")
	
	if scoreCard.QPSScore < 15 {
		fmt.Printf("  • QPS偏低 (%.1f): 考虑增加并发数或优化网络配置\n", qps)
	}
	if scoreCard.SuccessRateScore < 8 {
		fmt.Printf("  • 成功率偏低 (%.1f%%): 检查目标服务器负载和网络稳定性\n", successRate)
	}
	if scoreCard.ResponseTimeScore < 7 {
		fmt.Printf("  • 响应时间较慢: 优化连接复用和Keep-Alive设置\n")
	}
	if scoreCard.ProtocolScore < 15 {
		fmt.Printf("  • 启用更多协议测试 (WebSocket/gRPC/HTTP3) 可提高得分\n")
	}
	if scoreCard.ResourceScore < 7 {
		fmt.Printf("  • 资源使用较高: 考虑优化内存使用和协程管理\n")
	}
	
	if scoreCard.TotalScore >= 90 {
		fmt.Printf("  🎉 性能优秀! 系统表现良好\n")
	} else if scoreCard.TotalScore >= 80 {
		fmt.Printf("  👍 性能良好，还有提升空间\n")
	} else {
		fmt.Printf("  ⚠️  建议重点优化低分项以提升整体性能\n")
	}
}

// ===================================================================================
// --- 原有核心代码 (保持不变但做了优化) ---
// ===================================================================================

var (
	TargetURLs         []string
	GlobalCookies      = make(map[string]string)
	GlobalFixedHeaders = make(map[string]string)
	cookieMutex        sync.RWMutex
	globalTLSCache     tls.ClientSessionCache
	programStartTime   time.Time
)

type TestMode int
const (
	ModeNormal TestMode = iota
	ModeHangUp
	ModeOneByte
	ModeSlowReceive
)

type ProtocolType int
const (
	ProtocolHTTP ProtocolType = iota
	ProtocolGRPC
	ProtocolWebSocket
	ProtocolHTTP3
)

// 优化的统计信息结构体
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
	HTTP3Requests         int64
	CookieUpdates         int64
	TLSConnections        int64
	TimeoutCount          int64 // 新增超时计数
	ErrorTypes            map[string]int64
	ResponseTimes         []time.Duration
	StartTime             time.Time
	mu                    sync.RWMutex
}

type RequestCache struct {
	URLs     []string
	Payloads [][]byte
	Headers  []map[string]string
	Methods  []string
	mu       sync.RWMutex
	index    int64
}

// 优化的共享TLS缓存
type SharedTLSCache struct {
	mu    sync.RWMutex
	cache map[string]*tls.ClientSessionState
	hits  int64
	misses int64
}

func NewSharedTLSCache() *SharedTLSCache {
	return &SharedTLSCache{cache: make(map[string]*tls.ClientSessionState)}
}

func (c *SharedTLSCache) Put(key string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = cs
}

func (c *SharedTLSCache) Get(key string) (*tls.ClientSessionState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cs, ok := c.cache[key]
	if ok {
		atomic.AddInt64(&c.hits, 1)
	} else {
		atomic.AddInt64(&c.misses, 1)
	}
	return cs, ok
}

func (c *SharedTLSCache) GetStats() (hits, misses int64) {
	return atomic.LoadInt64(&c.hits), atomic.LoadInt64(&c.misses)
}

// 优化的User-Agent生成
var userAgentTemplates = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/125.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0",
}

var httpMethods = []string{"GET", "POST", "PUT", "HEAD", "DELETE", "PATCH", "OPTIONS"}
var contentTypes = []string{
	"application/json",
	"application/x-www-form-urlencoded", 
	"text/plain",
	"text/html",
	"application/xml",
	"multipart/form-data",
	"application/octet-stream",
}

func init() {
	mathrand.Seed(time.Now().UnixNano())
	programStartTime = time.Now()
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	if EnableSharedTLSSessionCache && !ForceNewTLSSessionPerConnection {
		globalTLSCache = NewSharedTLSCache()
	}
}

// 优化的初始化函数
func initLogFile() {
	logFileName := fmt.Sprintf("test_run_%s.log", time.Now().Format("20060102_150405"))
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("无法打开日志文件: %v", err)
	}
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.Printf("日志文件已创建: %s", logFileName)
}

func loadTargetURLs() error {
	file, err := os.Open("dependency.txt")
	if err != nil {
		return fmt.Errorf("无法打开dependency.txt文件: %v", err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
				log.Printf("警告: 跳过无效URL格式 (行 %d): %s", lineNum, line)
				continue
			}
			
			if _, err := url.ParseRequestURI(line); err != nil {
				log.Printf("警告: 跳过无效URL (行 %d): %s", lineNum, line)
				continue
			}
			TargetURLs = append(TargetURLs, line)
		}
	}
	
	if len(TargetURLs) == 0 {
		return fmt.Errorf("dependency.txt文件中没有找到有效的URL")
	}
	
	log.Printf("成功加载 %d 个目标URL", len(TargetURLs))
	return scanner.Err()
}

// 优化的计数写入器
type countingWriter struct {
	count int64
}

func (cw *countingWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	atomic.AddInt64(&cw.count, int64(n))
	return n, nil
}

// 优化的随机生成函数
func generateRandomUserAgent() string {
	if !EnableRandomUserAgent {
		return userAgentTemplates[0]
	}
	return userAgentTemplates[mathrand.Intn(len(userAgentTemplates))]
}

func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", 
		mathrand.Intn(254)+1, mathrand.Intn(256), mathrand.Intn(256), mathrand.Intn(254)+1)
}

// 优化的负载生成 - 提高性能
func generateRandomPayload() []byte {
	payloadType := mathrand.Intn(5) // 增加一种类型
	
	switch payloadType {
	case 0: // 轻量JSON
		data := map[string]interface{}{
			"id":        mathrand.Int63(),
			"timestamp": time.Now().Unix(),
			"type":      "load_test",
			"data":      fmt.Sprintf("test_%d", mathrand.Intn(10000)),
		}
		jsonData, _ := json.Marshal(data)
		return jsonData
		
	case 1: // 表单数据
		values := url.Values{}
		fieldCount := mathrand.Intn(5) + 1
		for i := 0; i < fieldCount; i++ {
			values.Add(fmt.Sprintf("field_%d", i), fmt.Sprintf("value_%d", mathrand.Int63()))
		}
		return []byte(values.Encode())
		
	case 2: // XML
		xml := fmt.Sprintf(`<?xml version="1.0"?><test><id>%d</id><data>test_%d</data></test>`, 
			mathrand.Int63(), mathrand.Intn(10000))
		return []byte(xml)
		
	case 3: // 二进制数据
		size := mathrand.Intn(512) + 64 // 64-576字节
		data := make([]byte, size)
		mathrand.Read(data)
		return data
		
	default: // 纯文本
		return []byte(fmt.Sprintf("test_payload_%d_%d", time.Now().UnixNano(), mathrand.Int63()))
	}
}

// 优化的路径生成
func generateRandomPath() string {
	if !EnableRandomPath {
		return ""
	}
	
	// 预定义路径池以提高性能
	commonPaths := []string{
		"api/v1/test", "api/v2/data", "user/profile", "admin/dashboard",
		"public/assets", "private/data", "test/endpoint", "health/check",
		"metrics/stats", "config/settings", "cache/clear", "auth/login",
	}
	
	if mathrand.Float32() < 0.6 {
		return commonPaths[mathrand.Intn(len(commonPaths))]
	}
	
	// 生成随机路径
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	pathLevels := mathrand.Intn(3) + 1
	var pathParts []string
	
	for i := 0; i < pathLevels; i++ {
		partLength := mathrand.Intn(8) + 3
		partBytes := make([]byte, partLength)
		for j := range partBytes {
			partBytes[j] = chars[mathrand.Intn(len(chars))]
		}
		pathParts = append(pathParts, string(partBytes))
	}
	
	return strings.Join(pathParts, "/")
}

func generateRandomQueryParams() string {
	if !EnableRandomQueryParams {
		return ""
	}
	
	commonParams := map[string][]string{
		"page":     {"1", "2", "10", "100"},
		"limit":    {"10", "50", "100", "500"},
		"sort":     {"asc", "desc", "name", "date"},
		"filter":   {"active", "all", "new", "old"},
		"format":   {"json", "xml", "csv"},
		"version":  {"v1", "v2", "latest"},
	}
	
	paramCount := mathrand.Intn(4) + 1
	var params []string
	
	keys := []string{"page", "limit", "sort", "filter", "format", "version"}
	used := make(map[string]bool)
	
	for i := 0; i < paramCount; i++ {
		key := keys[mathrand.Intn(len(keys))]
		if used[key] {
			continue
		}
		used[key] = true
		
		values := commonParams[key]
		value := values[mathrand.Intn(len(values))]
		params = append(params, fmt.Sprintf("%s=%s", key, value))
	}
	
	return strings.Join(params, "&")
}

func generateRandomURL() string {
	baseURL := TargetURLs[mathrand.Intn(len(TargetURLs))]
	
	if !EnableRandomPath && !EnableRandomQueryParams {
		return baseURL
	}
	
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	
	if EnableRandomPath && mathrand.Float32() < 0.7 {
		randomPath := generateRandomPath()
		if randomPath != "" {
			parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/") + "/" + randomPath
		}
	}
	
	if EnableRandomQueryParams && mathrand.Float32() < 0.5 {
		newParams := generateRandomQueryParams()
		if newParams != "" {
			if parsedURL.RawQuery != "" {
				parsedURL.RawQuery += "&" + newParams
			} else {
				parsedURL.RawQuery = newParams
			}
		}
	}
	
	return parsedURL.String()
}

// 优化的请求头生成
func generateRandomHeaders() map[string]string {
	headers := make(map[string]string)
	
	if EnableFixedHeaders {
		for k, v := range GlobalFixedHeaders {
			headers[k] = v
		}
		
		if _, exists := headers["User-Agent"]; !exists {
			headers["User-Agent"] = generateRandomUserAgent()
		}
		
		cookieMutex.RLock()
		if len(GlobalCookies) > 0 {
			var cookies []string
			for name, value := range GlobalCookies {
				cookies = append(cookies, fmt.Sprintf("%s=%s", name, value))
			}
			headers["Cookie"] = strings.Join(cookies, "; ")
		}
		cookieMutex.RUnlock()
	} else {
		headers["User-Agent"] = generateRandomUserAgent()
		headers["Accept"] = "*/*"
		headers["Accept-Language"] = "en-US,en;q=0.9,zh-CN;q=0.8"
		
		if EnableCompression {
			headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
		}
		
		headers["Connection"] = "keep-alive"
		headers["Cache-Control"] = "no-cache"
		
		// 随机添加现代浏览器头部
		if mathrand.Float32() < 0.4 {
			headers["Sec-Fetch-Mode"] = "cors"
			headers["Sec-Fetch-Site"] = "cross-site"
		}
		
		if mathrand.Float32() < 0.3 {
			referers := []string{
				"https://www.google.com/",
				"https://github.com/",
				"https://stackoverflow.com/",
			}
			headers["Referer"] = referers[mathrand.Intn(len(referers))]
		}
		
		if mathrand.Float32() < 0.2 {
			headers["X-Forwarded-For"] = generateRandomIP()
		}
	}
	
	return headers
}

func extractAndSaveCookies(resp *http.Response) {
	if !EnableFixedHeaders {
		return
	}
	
	cookieMutex.Lock()
	defer cookieMutex.Unlock()
	
	updated := false
	for _, cookie := range resp.Cookies() {
		if GlobalCookies[cookie.Name] != cookie.Value {
			GlobalCookies[cookie.Name] = cookie.Value
			updated = true
		}
	}
	
	if updated && EnableVerboseLogging {
		log.Printf("Cookie已更新，当前共有 %d 个Cookie", len(GlobalCookies))
	}
}

func buildCookieString() string {
	if !EnableFixedHeaders {
		return ""
	}
	
	cookieMutex.RLock()
	defer cookieMutex.RUnlock()
	
	if len(GlobalCookies) == 0 {
		return ""
	}
	
	var cookies []string
	for name, value := range GlobalCookies {
		cookies = append(cookies, fmt.Sprintf("%s=%s", name, value))
	}
	
	return strings.Join(cookies, "; ")
}

func initializeGlobalHeaders() error {
	if !EnableFixedHeaders {
		return nil
	}
	
	if len(TargetURLs) == 0 {
		return fmt.Errorf("没有可用的目标URL")
	}
	
	fmt.Println("正在初始化全局Headers和Cookies...")
	
	jar, _ := cookiejar.New(nil)
	client := createOptimizedHTTPClient()
	client.Jar = jar
	
	req, err := http.NewRequest("GET", TargetURLs[0], nil)
	if err != nil {
		return fmt.Errorf("创建初始化请求失败: %v", err)
	}
	
	req.Header.Set("User-Agent", generateRandomUserAgent())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if EnableCompression {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}
	
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("初始化请求失败: %v", err)
		return nil
	}
	defer resp.Body.Close()
	
	cookieMutex.Lock()
	for k, v := range req.Header {
		if len(v) > 0 {
			GlobalFixedHeaders[k] = v[0]
		}
	}
	
	extractAndSaveCookies(resp)
	cookieMutex.Unlock()
	
	fmt.Printf("全局Headers初始化完成，提取到 %d 个Cookie\n", len(GlobalCookies))
	return nil
}

// 优化的HTTP客户端创建
func createOptimizedHTTPClient() *http.Client {
	var tlsConfig *tls.Config
	
	if ForceNewTLSSessionPerConnection {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: IgnoreSSLErrors,
			MinVersion:         uint16(MinTLSVersion),
			MaxVersion:         uint16(MaxTLSVersion),
			ClientSessionCache: nil,
		}
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: IgnoreSSLErrors,
			MinVersion:         uint16(MinTLSVersion),
			MaxVersion:         uint16(MaxTLSVersion),
		}
		
		if EnableSharedTLSSessionCache && globalTLSCache != nil {
			tlsConfig.ClientSessionCache = globalTLSCache
		}
	}
	
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: KeepAliveTimeout,
		}).DialContext,
		ForceAttemptHTTP2:     strings.Contains(HTTPVersions, "h2"),
		MaxIdleConns:          MaxIdleConns,
		MaxIdleConnsPerHost:   MaxIdleConnsPerHost,
		IdleConnTimeout:       IdleConnTimeout,
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		ResponseHeaderTimeout: ResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
		DisableKeepAlives:     !EnableConnectionReuse,
		DisableCompression:    !EnableCompression,
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   RequestTimeout,
	}
}

func createHTTP3Client() *http.Client {
	if !EnableHTTP3 {
		return nil
	}
	
	return &http.Client{
		Transport: &http3.RoundTripper{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: IgnoreSSLErrors,
				MinVersion:         uint16(MinTLSVersion),
				MaxVersion:         uint16(MaxTLSVersion),
			},
		},
		Timeout: RequestTimeout,
	}
}

// 优化的缓存初始化
func initRequestCache(cache *RequestCache) {
	fmt.Println("初始化请求缓存...")
	cache.URLs = make([]string, CacheSize)
	cache.Payloads = make([][]byte, CacheSize)
	cache.Headers = make([]map[string]string, CacheSize)
	cache.Methods = make([]string, CacheSize)
	
	// 批量并发生成
	batchSize := CacheSize / runtime.NumCPU()
	if batchSize < 100 {
		batchSize = 100
	}
	
	var wg sync.WaitGroup
	for i := 0; i < CacheSize; i += batchSize {
		end := i + batchSize
		if end > CacheSize {
			end = CacheSize
		}
		
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for j := start; j < end; j++ {
				cache.URLs[j] = generateRandomURL()
				cache.Payloads[j] = generateRandomPayload()
				cache.Headers[j] = generateRandomHeaders()
				
				if UseRandomMethod {
					cache.Methods[j] = httpMethods[mathrand.Intn(len(httpMethods))]
				} else {
					cache.Methods[j] = "GET"
				}
			}
		}(i, end)
	}
	
	wg.Wait()
	fmt.Printf("缓存初始化完成，预生成 %d 个请求\n", CacheSize)
}

func getFromCache(cache *RequestCache) (string, []byte, map[string]string, string) {
	index := atomic.AddInt64(&cache.index, 1) % int64(CacheSize)
	
	cache.mu.RLock()
	url, payload, headers, method := cache.URLs[index], cache.Payloads[index], cache.Headers[index], cache.Methods[index]
	cache.mu.RUnlock()
	
	newHeaders := make(map[string]string)
	for k, v := range headers {
		newHeaders[k] = v
	}
	
	if EnableFixedHeaders && len(GlobalCookies) > 0 {
		if cookieStr := buildCookieString(); cookieStr != "" {
			newHeaders["Cookie"] = cookieStr
		}
	}
	
	// 降低缓存更新频率以提高性能
	if mathrand.Float32() < 0.01 { // 1% 概率更新
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
	
	return url, payload, newHeaders, method
}

// 限速读取器
type RateLimitedReader struct {
	r         io.Reader
	startTime time.Time
	bytesRead int64
}

func NewRateLimitedReader(r io.Reader) *RateLimitedReader {
	return &RateLimitedReader{r: r, startTime: time.Now()}
}

func (r *RateLimitedReader) Read(p []byte) (n int, err error) {
	if !EnableRateLimit {
		return r.r.Read(p)
	}
	
	elapsed := time.Since(r.startTime)
	if elapsed < RateLimitDuration {
		allowedBytes := int64(float64(elapsed.Seconds()) * float64(RateLimitSpeed) * 1024)
		if r.bytesRead >= allowedBytes {
			sleepTime := time.Duration(float64(r.bytesRead-allowedBytes)/(float64(RateLimitSpeed)*1024)) * time.Second
			if sleepTime > 0 && sleepTime < 5*time.Second {
				time.Sleep(sleepTime)
			}
		}
	}
	
	n, err = r.r.Read(p)
	r.bytesRead += int64(n)
	return n, err
}

type OneByteReader struct {
	r    io.Reader
	read bool
}

func (r *OneByteReader) Read(p []byte) (n int, err error) {
	if r.read {
		return 0, io.EOF
	}
	if len(p) > 1 {
		p = p[:1]
	}
	n, err = r.r.Read(p)
	if n > 0 {
		r.read = true
	}
	return
}

type SlowReader struct {
	r        io.Reader
	lastRead time.Time
	delay    time.Duration
}

func NewSlowReader(r io.Reader) *SlowReader {
	return &SlowReader{
		r:     r,
		delay: time.Duration(mathrand.Intn(1000)+200) * time.Millisecond,
	}
}

func (r *SlowReader) Read(p []byte) (n int, err error) {
	if !r.lastRead.IsZero() {
		if elapsed := time.Since(r.lastRead); elapsed < r.delay {
			time.Sleep(r.delay - elapsed)
		}
	}
	if len(p) > 1 {
		p = p[:1]
	}
	n, err = r.r.Read(p)
	r.lastRead = time.Now()
	return
}

// 优化的错误记录
func recordError(stats *Stats, errType string) {
	stats.mu.Lock()
	if stats.ErrorTypes == nil {
		stats.ErrorTypes = make(map[string]int64)
	}
	stats.ErrorTypes[errType]++
	stats.mu.Unlock()
}

func recordResponseTime(stats *Stats, duration time.Duration) {
	stats.mu.Lock()
	stats.ResponseTimes = append(stats.ResponseTimes, duration)
	if len(stats.ResponseTimes) > 50000 { // 增大响应时间样本
		stats.ResponseTimes = stats.ResponseTimes[5000:]
	}
	stats.mu.Unlock()
}

// 优化的WebSocket处理
func makeWebSocketRequest(url string, headers map[string]string, stats *Stats, mode TestMode) {
	dialer := websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: IgnoreSSLErrors,
			MinVersion:         uint16(MinTLSVersion),
			MaxVersion:         uint16(MaxTLSVersion),
		},
		EnableCompression: EnableCompression,
	}
	
	wsURL := strings.Replace(url, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	
	wsHeaders := make(http.Header)
	for k, v := range headers {
		wsHeaders.Set(k, v)
	}
	
	startTime := time.Now()
	conn, resp, err := dialer.Dial(wsURL, wsHeaders)
	if err != nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		if strings.Contains(err.Error(), "timeout") {
			atomic.AddInt64(&stats.TimeoutCount, 1)
		}
		recordError(stats, "WebSocket连接失败")
		return
	}
	defer conn.Close()
	
	if resp != nil {
		recordResponseTime(stats, time.Since(startTime))
		if resp.StatusCode != 101 {
			atomic.AddInt64(&stats.Non200Responses, 1)
			recordError(stats, fmt.Sprintf("WebSocket_HTTP_%d", resp.StatusCode))
		}
	}
	
	atomic.AddInt64(&stats.WSRequests, 1)
	
	testMessage := map[string]interface{}{
		"type":      "performance_test",
		"data":      "load_test_message",
		"timestamp": time.Now().Unix(),
		"id":        mathrand.Int63(),
	}
	
	if err := conn.WriteJSON(testMessage); err != nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		recordError(stats, "WebSocket发送失败")
		return
	}
	
	switch mode {
	case ModeOneByte:
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, _, _ = conn.ReadMessage()
		atomic.AddInt64(&stats.OneByteModeConns, 1)
	case ModeSlowReceive:
		for i := 0; i < 3; i++ {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
			time.Sleep(time.Duration(mathrand.Intn(1000)+300) * time.Millisecond)
		}
		atomic.AddInt64(&stats.SlowReceiveConns, 1)
	case ModeHangUp:
		atomic.AddInt64(&stats.HangingConnections, 1)
		time.Sleep(time.Duration(mathrand.Intn(180)+30) * time.Second)
	default:
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, message, err := conn.ReadMessage()
		if err == nil {
			atomic.AddInt64(&stats.TotalResponses, 1)
			atomic.AddInt64(&stats.TotalResponseSize, int64(len(message)))
		} else {
			recordError(stats, "WebSocket读取失败")
		}
	}
}

// 优化的gRPC处理
func makeGRPCRequest(target string, stats *Stats) {
	parsedURL, err := url.Parse(target)
	if err != nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		recordError(stats, "gRPC_URL解析失败")
		return
	}
	
	grpcTarget := parsedURL.Host
	if parsedURL.Port() == "" {
		if parsedURL.Scheme == "https" {
			grpcTarget += ":443"
		} else {
			grpcTarget += ":80"
		}
	}
	
	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	
	conn, err := grpc.DialContext(ctx, grpcTarget,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())

	if err != nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		if strings.Contains(err.Error(), "timeout") {
			atomic.AddInt64(&stats.TimeoutCount, 1)
		}
		recordError(stats, "gRPC连接失败")
		return
	}
	defer conn.Close()
	
	recordResponseTime(stats, time.Since(startTime))
	
	ctx = metadata.NewOutgoingContext(ctx,
		metadata.Pairs(
			"user-agent", generateRandomUserAgent(),
			"request-id", fmt.Sprintf("%d", mathrand.Int63())))

	atomic.AddInt64(&stats.GRPCRequests, 1)
	atomic.AddInt64(&stats.TotalRequests, 1)
	atomic.AddInt64(&stats.TotalResponses, 1)
}

func makeHTTP3Request(client *http.Client, method, url string, payload []byte, headers map[string]string, stats *Stats, mode TestMode) {
	if client == nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		recordError(stats, "HTTP3客户端未初始化")
		return
	}
	
	atomic.AddInt64(&stats.HTTP3Requests, 1)
	makeHTTPRequest(client, method, url, payload, headers, stats, mode)
}

// 分块读取器
type ChunkedReader struct {
	r io.Reader
}

func (c *ChunkedReader) Read(p []byte) (n int, err error) {
	if len(p) > 2048 { // 增大块大小以提高性能
		p = p[:2048]
	}
	return c.r.Read(p)
}

// 核心HTTP请求处理 - 高度优化版本
func makeHTTPRequest(client *http.Client, method, url string, payload []byte, headers map[string]string, stats *Stats, mode TestMode) {
	var req *http.Request
	var err error

	startTime := time.Now()
	
	if method == "POST" || method == "PUT" || method == "PATCH" {
		var bodyReader io.Reader = bytes.NewBuffer(payload)
		
		if EnableChunkedTransfer && mathrand.Float32() < 0.1 {
			bodyReader = &ChunkedReader{r: bodyReader}
		}
		
		req, err = http.NewRequest(method, url, bodyReader)
		if err != nil {
			atomic.AddInt64(&stats.FailedRequests, 1)
			recordError(stats, "请求创建失败")
			return
		}
		
		if EnableMultipartFormData && mathrand.Float32() < 0.1 {
			req.Header.Set("Content-Type", "multipart/form-data; boundary=----boundary123")
		} else {
			req.Header.Set("Content-Type", contentTypes[mathrand.Intn(len(contentTypes))])
		}
		
		if !EnableChunkedTransfer {
			req.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		}
	} else {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			atomic.AddInt64(&stats.FailedRequests, 1)
			recordError(stats, "请求创建失败")
			return
		}
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	requestDuration := time.Since(startTime)
	
	if err != nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		
		if strings.Contains(err.Error(), "timeout") {
			atomic.AddInt64(&stats.TimeoutCount, 1)
			recordError(stats, "请求超时")
		} else if strings.Contains(err.Error(), "connection refused") {
			recordError(stats, "连接被拒绝")
		} else if strings.Contains(err.Error(), "no such host") {
			recordError(stats, "主机不存在")
		} else {
			recordError(stats, "请求执行失败")
		}
		return
	}

	atomic.AddInt64(&stats.TotalRequests, 1)
	recordResponseTime(stats, requestDuration)

	if EnableFixedHeaders {
		extractAndSaveCookies(resp)
		if len(resp.Cookies()) > 0 {
			atomic.AddInt64(&stats.CookieUpdates, 1)
		}
	}
	
	if resp.TLS != nil {
		atomic.AddInt64(&stats.TLSConnections, 1)
	}

	defer resp.Body.Close()
	
	switch mode {
	case ModeNormal:
		var reader io.Reader = resp.Body
		if EnableRateLimit {
			reader = NewRateLimitedReader(resp.Body)
		}
		
		counter := &countingWriter{}
		io.Copy(counter, reader)
		atomic.AddInt64(&stats.TotalResponseSize, counter.count)
		
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			atomic.AddInt64(&stats.TotalResponses, 1)
		} else {
			atomic.AddInt64(&stats.Non200Responses, 1)
			recordError(stats, fmt.Sprintf("HTTP_%d", resp.StatusCode))
		}
		
	case ModeOneByte:
		io.Copy(io.Discard, &OneByteReader{r: resp.Body})
		atomic.AddInt64(&stats.OneByteModeConns, 1)
		
	case ModeSlowReceive:
		io.Copy(io.Discard, NewSlowReader(resp.Body))
		atomic.AddInt64(&stats.SlowReceiveConns, 1)
		
	case ModeHangUp:
		atomic.AddInt64(&stats.HangingConnections, 1)
		time.Sleep(time.Duration(mathrand.Intn(180)+30) * time.Second)
		return
	}
}

// 优化的工作协程
func worker(workerID int, cache *RequestCache, stats *Stats, httpClient, http3Client *http.Client, wg *sync.WaitGroup) {
	defer wg.Done()
	
	requestCount := TotalDownloads / NumConcurrentWorkers
	if workerID < TotalDownloads%NumConcurrentWorkers {
		requestCount++
	}
	
	for i := 0; i < requestCount; i++ {
		url, payload, headers, method := getFromCache(cache)
		
		// 优化的协议选择逻辑
		protocolChoice := mathrand.Intn(100)
		
		if EnableHTTP3 && protocolChoice < 5 && http3Client != nil {
			makeHTTP3Request(http3Client, method, url, payload, headers, stats, SelectedTestMode)
		} else if EnableWebSocket && protocolChoice < 15 {
			makeWebSocketRequest(url, headers, stats, SelectedTestMode)
		} else if EnableGRPC && protocolChoice < 20 {
			makeGRPCRequest(url, stats)
		} else {
			makeHTTPRequest(httpClient, method, url, payload, headers, stats, SelectedTestMode)
		}
		
		// 减少不必要的延迟
		if mathrand.Float32() < 0.05 {
			time.Sleep(time.Duration(mathrand.Intn(50)+10) * time.Millisecond)
		}
	}
}

// 优化的统计显示
func printStats(stats *Stats) {
	stats.mu.RLock()
	defer stats.mu.RUnlock()
	
	elapsed := time.Since(stats.StartTime)
	totalReq := atomic.LoadInt64(&stats.TotalRequests)
	totalResp := atomic.LoadInt64(&stats.TotalResponses)
	
	fmt.Printf("\n=== 详细统计信息 ===\n")
	fmt.Printf("运行时间: %v\n", elapsed)
	fmt.Printf("总请求数: %d\n", totalReq)
	fmt.Printf("成功响应: %d\n", totalResp)
	fmt.Printf("非2xx响应: %d\n", atomic.LoadInt64(&stats.Non200Responses))
	fmt.Printf("失败请求: %d\n", atomic.LoadInt64(&stats.FailedRequests))
	fmt.Printf("超时次数: %d\n", atomic.LoadInt64(&stats.TimeoutCount))
	fmt.Printf("响应总大小: %.2f MB\n", float64(atomic.LoadInt64(&stats.TotalResponseSize))/(1024*1024))
	
	if totalReq > 0 {
		qps := float64(totalReq) / elapsed.Seconds()
		successRate := float64(totalResp) / float64(totalReq) * 100
		fmt.Printf("请求速率: %.2f QPS\n", qps)
		fmt.Printf("成功率: %.2f%%\n", successRate)
		fmt.Printf("错误率: %.2f%%\n", float64(atomic.LoadInt64(&stats.FailedRequests))/float64(totalReq)*100)
	}
	
	// 响应时间统计
	if len(stats.ResponseTimes) > 0 {
		times := make([]time.Duration, len(stats.ResponseTimes))
		copy(times, stats.ResponseTimes)
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		
		var total time.Duration
		for _, rt := range times {
			total += rt
		}
		
		avg := total / time.Duration(len(times))
		p50 := times[len(times)/2]
		p95 := times[int(float64(len(times))*0.95)]
		p99 := times[int(float64(len(times))*0.99)]
		
		fmt.Printf("\n=== 响应时间分析 ===\n")
		fmt.Printf("平均响应时间: %v\n", avg)
		fmt.Printf("P50 响应时间: %v\n", p50)
		fmt.Printf("P95 响应时间: %v\n", p95)
		fmt.Printf("P99 响应时间: %v\n", p99)
		fmt.Printf("最快响应: %v\n", times[0])
		fmt.Printf("最慢响应: %v\n", times[len(times)-1])
	}
	
	// 协议统计
	fmt.Printf("\n=== 协议分布 ===\n")
	fmt.Printf("HTTP请求: %d\n", totalReq-atomic.LoadInt64(&stats.WSRequests)-atomic.LoadInt64(&stats.GRPCRequests)-atomic.LoadInt64(&stats.HTTP3Requests))
	if ws := atomic.LoadInt64(&stats.WSRequests); ws > 0 {
		fmt.Printf("WebSocket请求: %d\n", ws)
	}
	if grpc := atomic.LoadInt64(&stats.GRPCRequests); grpc > 0 {
		fmt.Printf("gRPC请求: %d\n", grpc)
	}
	if h3 := atomic.LoadInt64(&stats.HTTP3Requests); h3 > 0 {
		fmt.Printf("HTTP/3请求: %d\n", h3)
	}
	
	// TLS缓存统计
	if sharedCache, ok := globalTLSCache.(*SharedTLSCache); ok {
		hits, misses := sharedCache.GetStats()
		if hits > 0 || misses > 0 {
			fmt.Printf("\n=== TLS缓存效果 ===\n")
			fmt.Printf("缓存命中: %d\n", hits)
			fmt.Printf("缓存未命中: %d\n", misses)
			fmt.Printf("命中率: %.2f%%\n", float64(hits)/float64(hits+misses)*100)
		}
	}
	
	// 错误分析
	if len(stats.ErrorTypes) > 0 {
		fmt.Printf("\n=== 错误类型分布 ===\n")
		for errType, count := range stats.ErrorTypes {
			percentage := float64(count) / float64(totalReq) * 100
			fmt.Printf("%s: %d (%.2f%%)\n", errType, count, percentage)
		}
	}
}

// 优化的进度监控
func progressMonitor(stats *Stats, done chan bool) {
	if !EnableProgressBar {
		return
	}
	
	ticker := time.NewTicker(StatsUpdateInterval)
	defer ticker.Stop()
	
	lastRequests := int64(0)
	lastTime := time.Now()
	
	for {
		select {
		case <-ticker.C:
			current := atomic.LoadInt64(&stats.TotalRequests)
			responses := atomic.LoadInt64(&stats.TotalResponses)
			failed := atomic.LoadInt64(&stats.FailedRequests)
			
			now := time.Now()
			intervalDuration := now.Sub(lastTime)
			rps := float64(current-lastRequests) / intervalDuration.Seconds()
			
			progress := float64(current) / float64(TotalDownloads) * 100
			successRate := float64(responses) / math.Max(float64(current), 1) * 100
			
			fmt.Printf("\r[进度] %.1f%% | 请求: %d/%d | RPS: %.1f | 成功率: %.1f%% | 失败: %d", 
				progress, current, TotalDownloads, rps, successRate, failed)
			
			lastRequests = current
			lastTime = now
			
		case <-done:
			fmt.Println()
			return
		}
	}
}

// 健康检查优化
func performHealthCheck() error {
	fmt.Println("\n=== 执行健康检查 ===")
	
	if len(TargetURLs) == 0 {
		return fmt.Errorf("没有配置目标URL")
	}
	
	client := createOptimizedHTTPClient()
	successCount := 0
	checkCount := min(len(TargetURLs), 5)
	
	for i := 0; i < checkCount; i++ {
		targetURL := TargetURLs[i]
		fmt.Printf("检查 %s ... ", targetURL)
		
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			fmt.Printf("失败 (请求创建错误)\n")
			continue
		}
		
		req.Header.Set("User-Agent", generateRandomUserAgent())
		req.Header.Set("Accept", "*/*")
		
		start := time.Now()
		resp, err := client.Do(req)
		duration := time.Since(start)
		
		if err != nil {
			fmt.Printf("失败 (连接错误: %v)\n", err)
			continue
		}
		resp.Body.Close()
		
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			fmt.Printf("成功 (状态码: %d, 耗时: %v)\n", resp.StatusCode, duration)
			successCount++
		} else {
			fmt.Printf("警告 (状态码: %d)\n", resp.StatusCode)
		}
	}
	
	if successCount == 0 {
		return fmt.Errorf("所有目标URL健康检查失败")
	}
	
	fmt.Printf("健康检查完成: %d/%d 个目标可访问\n", successCount, checkCount)
	return nil
}

// 保存详细报告 (包含评分)
func saveDetailedReport(stats *Stats, totalDuration time.Duration, scoreCard *ScoreCard) {
	stats.mu.RLock()
	defer stats.mu.RUnlock()
	
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memUsageMB := float64(m.Alloc) / (1024 * 1024)
	
	report := map[string]interface{}{
		"test_info": map[string]interface{}{
			"version":           "2.1 Enhanced with Scoring",
			"start_time":        stats.StartTime.Format(time.RFC3339),
			"total_duration":    totalDuration.Seconds(),
			"go_version":        runtime.Version(),
			"cpu_cores":         runtime.NumCPU(),
			"memory_usage_mb":   memUsageMB,
			"active_goroutines": runtime.NumGoroutine(),
		},
		"test_config": map[string]interface{}{
			"total_downloads":        TotalDownloads,
			"concurrent_workers":     NumConcurrentWorkers,
			"cache_size":            CacheSize,
			"selected_test_mode":    SelectedTestMode,
			"enable_websocket":      EnableWebSocket,
			"enable_grpc":           EnableGRPC,
			"enable_http3":          EnableHTTP3,
			"enable_random_path":    EnableRandomPath,
			"enable_random_params":  EnableRandomQueryParams,
			"use_random_method":     UseRandomMethod,
			"enable_fixed_headers":  EnableFixedHeaders,
			"http_versions":         HTTPVersions,
		},
		"performance_results": map[string]interface{}{
			"total_requests":       atomic.LoadInt64(&stats.TotalRequests),
			"successful_responses": atomic.LoadInt64(&stats.TotalResponses),
			"failed_requests":      atomic.LoadInt64(&stats.FailedRequests),
			"timeout_count":        atomic.LoadInt64(&stats.TimeoutCount),
			"total_response_size":  atomic.LoadInt64(&stats.TotalResponseSize),
			"requests_per_second":  float64(atomic.LoadInt64(&stats.TotalRequests)) / totalDuration.Seconds(),
			"success_rate_percent": float64(atomic.LoadInt64(&stats.TotalResponses)) / math.Max(float64(atomic.LoadInt64(&stats.TotalRequests)), 1) * 100,
			"error_rate_percent":   float64(atomic.LoadInt64(&stats.FailedRequests)) / math.Max(float64(atomic.LoadInt64(&stats.TotalRequests)), 1) * 100,
		},
		"protocol_stats": map[string]interface{}{
			"http_requests":    atomic.LoadInt64(&stats.TotalRequests) - atomic.LoadInt64(&stats.WSRequests) - atomic.LoadInt64(&stats.GRPCRequests) - atomic.LoadInt64(&stats.HTTP3Requests),
			"websocket_requests": atomic.LoadInt64(&stats.WSRequests),
			"grpc_requests":    atomic.LoadInt64(&stats.GRPCRequests),
			"http3_requests":   atomic.LoadInt64(&stats.HTTP3Requests),
			"tls_connections":  atomic.LoadInt64(&stats.TLSConnections),
		},
		"score_card": map[string]interface{}{
			"qps_score":           scoreCard.QPSScore,
			"success_rate_score":  scoreCard.SuccessRateScore,
			"response_time_score": scoreCard.ResponseTimeScore,
			"error_rate_score":    scoreCard.ErrorRateScore,
			"timeout_score":       scoreCard.TimeoutScore,
			"protocol_score":      scoreCard.ProtocolScore,
			"resource_score":      scoreCard.ResourceScore,
			"total_score":         scoreCard.TotalScore,
			"grade":              scoreCard.Grade,
		},
		"error_analysis": stats.ErrorTypes,
		"target_urls":    TargetURLs,
		"timestamp":      time.Now().Format(time.RFC3339),
	}
	
	// 响应时间统计
	if len(stats.ResponseTimes) > 0 {
		times := make([]time.Duration, len(stats.ResponseTimes))
		copy(times, stats.ResponseTimes)
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		
		var total time.Duration
		for _, rt := range times {
			total += rt
		}
		avg := total / time.Duration(len(times))
		
		report["response_time_analysis"] = map[string]interface{}{
			"average_ms":    float64(avg.Nanoseconds()) / 1e6,
			"min_ms":        float64(times[0].Nanoseconds()) / 1e6,
			"max_ms":        float64(times[len(times)-1].Nanoseconds()) / 1e6,
			"p50_ms":        float64(times[len(times)/2].Nanoseconds()) / 1e6,
			"p95_ms":        float64(times[int(float64(len(times))*0.95)].Nanoseconds()) / 1e6,
			"p99_ms":        float64(times[int(float64(len(times))*0.99)].Nanoseconds()) / 1e6,
			"sample_count":  len(times),
		}
	}
	
	fileName := fmt.Sprintf("detailed_report_%s.json", time.Now().Format("20060102_150405"))
	file, err := os.Create(fileName)
	if err != nil {
		log.Printf("无法创建报告文件: %v", err)
		return
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		log.Printf("无法保存报告: %v", err)
		return
	}
	
	log.Printf("详细报告已保存到: %s", fileName)
}

// 创建示例配置文件
func createSampleDependencyFile() {
	if _, err := os.Stat("dependency.txt"); os.IsNotExist(err) {
		fmt.Println("创建示例dependency.txt文件...")
		
		sampleContent := `# 网络流量测试目标URL配置文件
# 每行一个URL，支持HTTP和HTTPS
# 以#开头的行为注释

# 高性能测试目标
https://httpbin.org/get
https://httpbin.org/post
https://httpbin.org/put
https://httpbin.org/delete
https://httpbin.org/status/200
https://httpbin.org/json
https://httpbin.org/delay/1
https://httpbin.org/gzip

# WebSocket测试 (如果支持)
# wss://echo.websocket.org/

# 自定义目标 - 替换为你的测试目标
# https://your-api.example.com/v1/test
# https://your-api.example.com/v2/health
# http://localhost:8080/api/test
`
		
		err := os.WriteFile("dependency.txt", []byte(sampleContent), 0644)
		if err != nil {
			log.Printf("警告: 无法创建示例dependency.txt文件: %v", err)
		} else {
			fmt.Println("已创建示例dependency.txt文件，请编辑后重新运行")
		}
	}
}

func validateConfiguration() error {
	if TotalDownloads <= 0 || NumConcurrentWorkers <= 0 {
		return fmt.Errorf("请求数和并发数必须大于0")
	}
	
	if NumConcurrentWorkers > TotalDownloads {
		return fmt.Errorf("并发数不能大于总请求数")
	}
	
	if CacheSize <= 0 {
		return fmt.Errorf("缓存大小必须大于0")
	}
	
	if MinTLSVersion > MaxTLSVersion {
		return fmt.Errorf("TLS版本配置错误")
	}
	
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 主函数 - 集成评分系统
func main() {
	fmt.Printf("=== 网络流量测试工具 v2.1 (含评分系统) ===\n")
	fmt.Printf("开始时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("Go版本: %s | CPU核心: %d | 最大并发: %d | 总请求: %d\n", 
		runtime.Version(), runtime.NumCPU(), NumConcurrentWorkers, TotalDownloads)
	
	modeNames := map[TestMode]string{
		ModeNormal: "正常模式", ModeHangUp: "挂起模式", 
		ModeOneByte: "单字节模式", ModeSlowReceive: "慢速接收模式",
	}
	fmt.Printf("测试模式: %s\n", modeNames[SelectedTestMode])
	
	createSampleDependencyFile()
	
	if err := validateConfiguration(); err != nil {
		log.Fatalf("配置验证失败: %v", err)
	}
	
	initLogFile()
	
	if err := loadTargetURLs(); err != nil {
		log.Fatalf("加载目标URL失败: %v", err)
	}
	
	if err := performHealthCheck(); err != nil {
		log.Printf("健康检查失败: %v", err)
		fmt.Print("是否继续? (y/N): ")
		
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(input)) != "y" {
			return
		}
	}
	
	stats := &Stats{
		StartTime:     time.Now(),
		ErrorTypes:    make(map[string]int64),
		ResponseTimes: make([]time.Duration, 0, 10000),
	}
	
	cache := &RequestCache{}
	initRequestCache(cache)
	
	if err := initializeGlobalHeaders(); err != nil {
		log.Printf("警告: 初始化Headers失败: %v", err)
	}
	
	httpClient := createOptimizedHTTPClient()
	var http3Client *http.Client
	if EnableHTTP3 {
		http3Client = createHTTP3Client()
	}
	
	fmt.Printf("\n=== 开始流量测试 ===\n")
	fmt.Printf("目标URL: %d 个\n", len(TargetURLs))
	
	progressDone := make(chan bool, 1)
	if EnableProgressBar {
		go progressMonitor(stats, progressDone)
	}
	
	var wg sync.WaitGroup
	startTime := time.Now()
	
	// 分批启动协程
	batchSize := 50
	for i := 0; i < NumConcurrentWorkers; i += batchSize {
		end := min(i+batchSize, NumConcurrentWorkers)
		
		for j := i; j < end; j++ {
			wg.Add(1)
			go worker(j, cache, stats, httpClient, http3Client, &wg)
		}
		
		if end < NumConcurrentWorkers {
			time.Sleep(100 * time.Millisecond)
		}
	}
	
	wg.Wait()
	
	if EnableProgressBar {
		progressDone <- true
	}
	
	totalDuration := time.Since(startTime)
	
	fmt.Printf("\n=== 测试完成 ===\n")
	fmt.Printf("总耗时: %v\n", totalDuration)
	
	printStats(stats)
	
	// 计算并显示评分
	if EnableScoring {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		memUsageMB := float64(m.Alloc) / (1024 * 1024)
		
		scoreCard := calculateScore(stats, totalDuration, memUsageMB, runtime.NumGoroutine())
		printScoreReport(scoreCard, stats, totalDuration)
		
		// 保存包含评分的详细报告
		saveDetailedReport(stats, totalDuration, scoreCard)
	}
	
	// 性能总结
	fmt.Printf("\n=== 性能总结 ===\n")
	if totalReq := atomic.LoadInt64(&stats.TotalRequests); totalReq > 0 {
		qps := float64(totalReq) / totalDuration.Seconds()
		fmt.Printf("平均QPS: %.2f\n", qps)
		
		if totalSize := atomic.LoadInt64(&stats.TotalResponseSize); totalSize > 0 {
			bandwidth := float64(totalSize) / (1024 * 1024) / totalDuration.Seconds()
			fmt.Printf("平均带宽: %.2f MB/s\n", bandwidth)
		}
		
		efficiency := qps / float64(NumConcurrentWorkers)
		fmt.Printf("并发效率: %.2f 请求/秒/协程\n", efficiency)
	}
	
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("峰值内存: %.2f MB\n", float64(m.Sys)/(1024*1024))
	fmt.Printf("GC次数: %d\n", m.NumGC)
	fmt.Printf("程序总运行时间: %v\n", time.Since(programStartTime))
	
	fmt.Println("\n测试完成! 🎯")
}
