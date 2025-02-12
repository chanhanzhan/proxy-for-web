package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"database/sql"

	"github.com/fsnotify/fsnotify"
	_ "modernc.org/sqlite"
	"github.com/gorilla/mux"
)

//go:embed Template/index.html
var indexHTML string

var (
	proxyFile, cnFile, httpFile string
	fileModTime                 = make(map[string]time.Time)
	config                      Config
	db                          *sql.DB
	mu                          sync.Mutex // 用于保护访问日志的并发安全
)

// 配置结构体
type Config struct {
	PoweredBy      string    `json:"poweredBy"`
	Token          string    `json:"token"`
	Port           int       `json:"port"`
	ServerLocation string    `json:"serverLocation"`
	IPControl      IPControl `json:"ipControl"`
	APIMethod      string    `json:"apiMethod"`  // "post", "get", "both"
}

type IPControl struct {
	Mode      string   `json:"mode"`      // "none", "blacklist", "whitelist"
	Blacklist []string `json:"blacklist"`
	Whitelist []string `json:"whitelist"`
}

// IPControl配置结构体
type IPControlConfig struct {
	Mode      string   `json:"mode"`
	Blacklist []string `json:"blacklist"`
	Whitelist []string `json:"whitelist"`
}

// 访问日志结构体
type AccessLog struct {
	IP        string
	Timestamp time.Time
}

// 添加颜色常量
const (
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorReset   = "\033[0m"
)

// 日志工具函数
func colorLog(color, level, format string, v ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf(format, v...)
	log.Printf("%s%s [%s] %s%s\n", color, timestamp, level, logMessage, colorReset)
}

func logInfo(format string, v ...interface{}) {
	colorLog(colorGreen, "INFO", format, v...)
}

func logError(format string, v ...interface{}) {
	colorLog(colorRed, "ERROR", format, v...)
}

func logWarn(format string, v ...interface{}) {
	colorLog(colorYellow, "WARN", format, v...)
}

func logDebug(format string, v ...interface{}) {
	colorLog(colorCyan, "DEBUG", format, v...)
}

func logAPI(r *http.Request, status int, message string) {
	method := fmt.Sprintf("%s%s%s", colorMagenta, r.Method, colorReset)
	path := fmt.Sprintf("%s%s%s", colorBlue, r.URL.Path, colorReset)
	statusColor := colorGreen
	if status >= 400 {
		statusColor = colorRed
	} else if status >= 300 {
		statusColor = colorYellow
	}
	statusStr := fmt.Sprintf("%s%d%s", statusColor, status, colorReset)
	
	clientIP := getClientIP(r)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	log.Printf("%s [API] %s %s %s from %s - %s\n",
		timestamp, method, path, statusStr, clientIP, message)
}

func init() {
	readConfig()
	updateFiles()
	updateFileModTime(proxyFile)
	updateFileModTime(cnFile)
	updateFileModTime(httpFile)
	initDB()
	go watchFiles()
}

func readConfig() {
	if _, err := os.Stat("config.json"); os.IsNotExist(err) {
		defaultConfig := Config{
			PoweredBy:      "@CLFchen",
			Token:         "123456788",
			Port:          8080,
			ServerLocation: "当前测试服务器位于: xxx",
			APIMethod:      "both",
		}
		
		data, err := json.MarshalIndent(defaultConfig, "", "    ")
		if err != nil {
			logError("创建默认配置失败: %v", err)
			os.Exit(1)
		}
		
		if err := os.WriteFile("config.json", data, 0644); err != nil {
			logError("写入默认配置失败: %v", err)
			os.Exit(1)
		}
		
		logInfo("已创建默认配置文件 config.json")
		config = defaultConfig
		return
	}

	file, err := os.Open("config.json")
	if err != nil {
		logError("读取 config.json 时出错: %v", err)
		os.Exit(1)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		logError("解析 config.json 时出错: %v", err)
		os.Exit(1)
	}
	logInfo("成功加载配置文件 config.json")
}

func updateFiles() {
	proxyFile = findFile("proxy.txt")
	cnFile = findFile("cn.txt")
	httpFile = findFile("http.txt")
}

func findFile(filename string) string {
	var file string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && info.Name() == filename {
			file = path
		}
		return nil
	})
	if err != nil {
		log.Printf("查找文件 %s 时出错: %v\n", filename, err)
	}
	return file
}

func updateFileModTime(filePath string) {
	if filePath == "" {
		return
	}
	info, err := os.Stat(filePath)
	if err != nil {
		log.Printf("无法获取文件 %s 的状态: %v\n", filePath, err)
		return
	}
	fileModTime[filePath] = info.ModTime()
}

func toBeijingTime(t time.Time) string {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		log.Printf("加载时区失败: %v\n", err)
		return t.Format("2006-01-02 15:04:05")
	}
	return t.In(location).Format("2006-01-02 15:04:05")
}

func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func logRequest(r *http.Request, status int, size int64) {
	if r.URL.Path == "/favicon.ico" {
		return
	}

	ip := getClientIP(r)
	timestamp := time.Now()

	_, err := db.Exec("INSERT INTO access_logs (ip, timestamp) VALUES (?, ?)", ip, timestamp)
	if err != nil {
		log.Printf("插入访问日志失败: %v\n", err)
	}

	_, err = db.Exec("INSERT INTO route_logs (route, count) VALUES (?, 1) ON CONFLICT(route) DO UPDATE SET count = count + 1", r.URL.Path)
	if err != nil {
		log.Printf("插入路由日志失败: %v\n", err)
	}

	log.Printf(`时间: %s
IP 地址: %s
请求方法: %s
请求路径: %s
响应状态: %d
响应内容大小: %d 字节
来源: "%s"
用户代理: "%s"`,
		toBeijingTime(timestamp),
		ip,
		r.Method,
		r.URL.Path,
		status,
		size,
		r.Referer(),
		r.UserAgent(),
	)
}

func countLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var count int
	buffer := make([]byte, 32*1024)
	for {
		c, err := file.Read(buffer)
		count += countNewlines(buffer[:c])
		if err != nil {
			break
		}
	}
	return count, nil
}

func countNewlines(data []byte) int {
	count := 0
	for _, b := range data {
		if b == '\n' {
			count++
		}
	}
	return count
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./data.db")
	if err != nil {
		log.Fatalf("无法打开数据库: %v\n", err)
	}

	// 创建访问日志表
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS access_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT,
		timestamp DATETIME
	)`)
	if err != nil {
		log.Fatalf("创建访问日志表失败: %v\n", err)
	}

	// 创建路由日志表，添加 UNIQUE 约束
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS route_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		route TEXT UNIQUE,
		count INTEGER DEFAULT 0
	)`)
	if err != nil {
		log.Fatalf("创建路由日志表失败: %v\n", err)
	}

	// 清理旧日志
	_, err = db.Exec(`DELETE FROM access_logs WHERE timestamp < DATETIME('now', '-48 hours')`)
	if err != nil {
		log.Fatalf("删除旧日志失败: %v\n", err)
	}

	// 添加索引以提高查询性能
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp)`)
	if err != nil {
		log.Printf("创建时间戳索引失败: %v\n", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_access_logs_ip ON access_logs(ip)`)
	if err != nil {
		log.Printf("创建 IP 索引失败: %v\n", err)
	}
}

func countVisitorsLast24Hours() int {
	rows, err := db.Query(`SELECT COUNT(DISTINCT ip) FROM access_logs WHERE timestamp >= DATETIME('now', '-24 hours')`)
	if err != nil {
		log.Printf("查询访问日志失败: %v\n", err)
		return 0
	}
	defer rows.Close()

	var count int
	if rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			log.Printf("扫描结果失败: %v\n", err)
			return 0
		}
	}
	return count
}

func getTopIPs(limit int) ([]string, error) {
	rows, err := db.Query(`SELECT ip, COUNT(*) as count FROM access_logs GROUP BY ip ORDER BY count DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		var count int
		err = rows.Scan(&ip, &count)
		if err != nil {
			return nil, err
		}
		ips = append(ips, fmt.Sprintf("%s (%d 次)", ip, count))
	}
	return ips, nil
}

func getTopRoutes(limit int) ([]string, error) {
	rows, err := db.Query(`SELECT route, count FROM route_logs ORDER BY count DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var routes []string
	for rows.Next() {
		var route string
		var count int
		err = rows.Scan(&route, &count)
		if err != nil {
			return nil, err
		}
		routes = append(routes, fmt.Sprintf("%s (%d 次)", route, count))

	}
	return routes, nil
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Path)

	if filename != proxyFile && filename != cnFile && filename != httpFile {
		http.Error(w, "文件不存在", http.StatusNotFound)
		logRequest(r, http.StatusNotFound, 0)
		return
	}

	info, err := os.Stat(filename)
	if err != nil {
		http.Error(w, "文件无法访问", http.StatusInternalServerError)
		logRequest(r, http.StatusInternalServerError, 0)
		return
	}

	http.ServeFile(w, r, filename)
	logRequest(r, http.StatusOK, info.Size())
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		ProxyLines     int
		CNLines        int
		HTTPLines      int
		ProxyUpdated   string
		CNUpdated      string
		HTTPUpdated    string
		PoweredBy      string
		ServerLocation string
	}{
		PoweredBy:      config.PoweredBy,
		ServerLocation: config.ServerLocation,
	}

	if proxyFile != "" {
		lines, err := countLines(proxyFile)
		if err == nil {
			data.ProxyLines = lines
			data.ProxyUpdated = toBeijingTime(fileModTime[proxyFile])
		}
	}

	if cnFile != "" {
		lines, err := countLines(cnFile)
		if err == nil {
			data.CNLines = lines
			data.CNUpdated = toBeijingTime(fileModTime[cnFile])
		}
	}

	if httpFile != "" {
		lines, err := countLines(httpFile)
		if err == nil {
			data.HTTPLines = lines
			data.HTTPUpdated = toBeijingTime(fileModTime[httpFile])
		}
	}

	renderTemplate(w, "index.html", indexHTML, data)
	logRequest(r, http.StatusOK, int64(len(indexHTML)))
}

func addAccessLog(ip string) {
	mu.Lock()
	defer mu.Unlock()
	_, err := db.Exec("INSERT INTO access_logs (ip, timestamp) VALUES (?, ?)", ip, time.Now())
	if err != nil {
		log.Printf("插入访问日志失败: %v\n", err)
	}
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	visitors := countVisitorsLast24Hours()

	topIPs, err := getTopIPs(15)
	if err != nil {
		log.Printf("查询热门 IP 失败: %v\n", err)
	}

	topRoutes, err := getTopRoutes(15)
	if err != nil {
		log.Printf("查询热门路由失败: %v\n", err)
	}

	data := struct {
		Visitors       int
		LastUpdateTime string
		TopIPs         []string
		TopRoutes      []string
	}{
		Visitors:       visitors,
		LastUpdateTime: toBeijingTime(time.Now()),
		TopIPs:         topIPs,
		TopRoutes:      topRoutes,
	}

	statsTemplate := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>访问统计</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(to right,rgb(6, 236, 94),rgb(12, 216, 243)); /* 绿的才是最好看的！ */
            margin: 0;
            padding: 0;
        }
        .container {
            width: 80%;
            margin: 50px auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            text-align: center;
            color: #333;
        }
        p {
            font-size: 1.2em;
            line-height: 1.6;
            color: #555;
        }
        .stats {
            margin-top: 20px;
            padding: 10px;
            background-color: #f9f9f9;
            border-left: 5px solid #4CAF50;
        }
        .stats p {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>24 小时访问统计</h1>
        <div class="stats">
            <p><strong>过去 24 小时的访问人数:</strong> {{.Visitors}}</p>
            <p><strong>统计更新时间:</strong> {{.LastUpdateTime}}</p>
            <h2>热门 IP</h2>
            <ul>
                {{range .TopIPs}}
                <li>{{.}}</li>
                {{end}}
            </ul>
            <h2>热门路由</h2>
            <ul>
                {{range .TopRoutes}}
                <li>{{.}}</li>
                {{end}}
            </ul>
        </div>
    </div>
</body>
</html>
`

	renderTemplate(w, "stats.html", statsTemplate, data)
	logRequest(r, http.StatusOK, int64(len(statsTemplate)))
}

func renderTemplate(w http.ResponseWriter, tmplName, tmplContent string, data interface{}) {
	tmpl, err := template.New(tmplName).Parse(tmplContent)
	if err != nil {
		http.Error(w, "模板渲染失败", http.StatusInternalServerError)
		log.Printf("渲染模板失败: %v", err)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "模板渲染失败", http.StatusInternalServerError)
		log.Printf("渲染模板失败: %v", err)
	}
}

func watchFiles() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("创建文件监视器失败: %v\n", err)
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
					if event.Name == proxyFile || event.Name == cnFile || event.Name == httpFile {
						updateFileModTime(event.Name)
						updateFileInfo(event.Name)
						applyFileChanges(event.Name)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("文件监视器错误: %v\n", err)
			}
		}
	}()

	files := []string{proxyFile, cnFile, httpFile}
	for _, file := range files {
		if file != "" {
			err = watcher.Add(file)
			if err != nil {
				log.Printf("添加文件到监视器失败: %v\n", err)
			}
		}
	}
}

func applyFileChanges(filePath string) {
	// 根据文件路径应用相应的修改逻辑
	if filePath == proxyFile {
		// 处理 proxyFile 的修改
		log.Printf("应用 proxyFile 的修改")
		// ...添加具体的处理逻辑...
	} else if filePath == cnFile {
		// 处理 cnFile 的修改
		log.Printf("应用 cnFile 的修改")
		// ...添加具体的处理逻辑...
	} else if filePath == httpFile {
		// 处理 httpFile 的修改
		log.Printf("应用 httpFile 的修改")
		// ...添加具体的处理逻辑...
	}
}

func updateFileInfo(filePath string) {
	if filePath == "" {
		return
	}
	info, err := os.Stat(filePath)
	if err != nil {
		log.Printf("无法获取文件 %s 的状态: %v\n", filePath, err)
		return
	}
	fileModTime[filePath] = info.ModTime()
	log.Printf("文件 %s 的最新修改时间: %s\n", filePath, toBeijingTime(info.ModTime()))
}

// 加载主配置
func loadConfig() Config {
	mu.Lock()
	defer mu.Unlock()
	
	file, err := os.Open("config.json")
	if err != nil {
		log.Printf("读取 config.json 时出错: %v，使用默认配置\n", err)
		return Config{
			PoweredBy: "Unknown",
			Token:    "default_token",
			Port:     8080,
		}
	}
	defer file.Close()

	var cfg Config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		log.Printf("解析 config.json 时出错: %v，使用默认配置\n", err)
		return Config{
			PoweredBy: "Unknown",
			Token:    "default_token",
			Port:     8080,
		}
	}
	return cfg
}

// 加载IP控制配置
func loadIPControlConfig() IPControlConfig {
	mu.Lock()
	defer mu.Unlock()
	
	if _, err := os.Stat("ipcontrol.json"); os.IsNotExist(err) {
		defaultConfig := IPControlConfig{
			Mode:      "none",
			Blacklist: []string{},
			Whitelist: []string{"127.0.0.1"},
		}
		
		data, err := json.MarshalIndent(defaultConfig, "", "    ")
		if err != nil {
			logError("创建默认 IP 控制配置失败: %v", err)
			return defaultConfig
		}
		
		if err := os.WriteFile("ipcontrol.json", data, 0644); err != nil {
			logError("写入默认 IP 控制配置失败: %v", err)
			return defaultConfig
		}
		
		logInfo("已创建默认配置文件 ipcontrol.json")
		return defaultConfig
	}
	
	file, err := os.Open("ipcontrol.json")
	if err != nil {
		logError("读取 ipcontrol.json 时出错: %v", err)
		return IPControlConfig{Mode: "none"}
	}
	defer file.Close()

	var cfg IPControlConfig
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		logError("解析 ipcontrol.json 时出错: %v", err)
		return IPControlConfig{Mode: "none"}
	}
	return cfg
}

// 保存IP控制配置
func saveIPControlConfig(cfg IPControlConfig) error {
	mu.Lock()
	defer mu.Unlock()
	
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}
	
	return os.WriteFile("ipcontrol.json", data, 0644)
}

// IP控制
func ipControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查 token
		token := r.Header.Get("Authorization")
		config := loadConfig()
		if token == config.Token {
			// 如果有有效的 token，直接放行绕过黑白名单(安全问题?我不管!)
			next.ServeHTTP(w, r)
			return
		}

		// 没有有效 token 时检查黑白名单
		clientIP := getClientIP(r)
		ipConfig := loadIPControlConfig()

		switch ipConfig.Mode {
		case "blacklist":
			for _, ip := range ipConfig.Blacklist {
				if ip == clientIP {
					http.Error(w, "403 Why not play Genshin Impact?", http.StatusForbidden)
					return
				}
			}
		case "whitelist":
			allowed := false
			for _, ip := range ipConfig.Whitelist {
				if ip == clientIP {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "403 Why not play Genshin Impact?", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// 添加IP到黑名单
func addToBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !validateToken(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ipConfig := loadIPControlConfig()
	ipConfig.Blacklist = append(ipConfig.Blacklist, req.IP)
	if err := saveIPControlConfig(ipConfig); err != nil {
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// 从黑名单移除IP
func removeFromBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !validateToken(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ipConfig := loadIPControlConfig()
	for i, ip := range ipConfig.Blacklist {
		if ip == req.IP {
			ipConfig.Blacklist = append(ipConfig.Blacklist[:i], ipConfig.Blacklist[i+1:]...)
			break
		}
	}
	if err := saveIPControlConfig(ipConfig); err != nil {
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// 添加IP到白名单
func addToWhitelist(w http.ResponseWriter, r *http.Request) {
	config := loadConfig()
	
	// 检查请求方法
	if (config.APIMethod == "post" && r.Method != http.MethodPost) ||
	   (config.APIMethod == "get" && r.Method != http.MethodGet) ||
	   (config.APIMethod != "both" && r.Method != http.MethodPost && r.Method != http.MethodGet) {
		sendJSONResponse(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	if !validateToken(r) {
		sendJSONResponse(w, http.StatusUnauthorized, Response{
			Success: false,
			Message: "Unauthorized: Invalid token",
		})
		return
	}

	var req struct {
		IP string `json:"ip"`
	}

	// 根据请求方法解析参数
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONResponse(w, http.StatusBadRequest, Response{
				Success: false,
				Message: "Invalid request body: " + err.Error(),
			})
			return
		}
	} else {
		req.IP = r.URL.Query().Get("ip")
	}

	if req.IP == "" {
		sendJSONResponse(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "IP address is required",
		})
		return
	}

	ipConfig := loadIPControlConfig()
	// 检查 IP 是否已存在
	for _, ip := range ipConfig.Whitelist {
		if ip == req.IP {
			sendJSONResponse(w, http.StatusOK, Response{
				Success: false,
				Message: "IP already exists in whitelist",
			})
			return
		}
	}
	
	ipConfig.Whitelist = append(ipConfig.Whitelist, req.IP)
	if err := saveIPControlConfig(ipConfig); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to save configuration: " + err.Error(),
		})
		return
	}

	sendJSONResponse(w, http.StatusOK, Response{
		Success: true,
		Message: "IP added to whitelist successfully",
	})
}

// 响应结构体辅助函数
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func sendJSONResponse(w http.ResponseWriter, status int, response Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
	
	// 记录 API 访问日志
	r := w.(interface{ Request() *http.Request }).Request()
	logAPI(r, status, response.Message)
}

// 从白名单移除IP
func removeFromWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !validateToken(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ipConfig := loadIPControlConfig()
	for i, ip := range ipConfig.Whitelist {
		if ip == req.IP {
			ipConfig.Whitelist = append(ipConfig.Whitelist[:i], ipConfig.Whitelist[i+1:]...)
			break
		}
	}
	if err := saveIPControlConfig(ipConfig); err != nil {
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// 验证token
func validateToken(r *http.Request) bool {
	config := loadConfig()
	token := r.Header.Get("Authorization")
	return token == config.Token
}

func main() {
	router := mux.NewRouter()
	router.Use(ipControlMiddleware)

	// 注册路由
	router.HandleFunc("/", rootHandler)
	router.HandleFunc("/proxy.txt", fileHandler)
	router.HandleFunc("/cn.txt", fileHandler)
	router.HandleFunc("/http.txt", fileHandler)
	router.HandleFunc("/stats", statsHandler)

	// API 路由
	router.HandleFunc("/api/blacklist/add", addToBlacklist)
	router.HandleFunc("/api/blacklist/remove", removeFromBlacklist)
	router.HandleFunc("/api/whitelist/add", addToWhitelist)
	router.HandleFunc("/api/whitelist/remove", removeFromWhitelist)

	logInfo("服务已启动，监听端口 :%d", config.Port)
	logInfo("API 方法限制: %s", config.APIMethod)
	ipConfig := loadIPControlConfig()
	logInfo("IP 控制模式: %s", ipConfig.Mode)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), router))
}
