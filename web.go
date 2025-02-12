package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
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
	"github.com/gorilla/mux"
	_ "modernc.org/sqlite"
)

//go:embed Template/index.html
var indexHTML string

//go:embed Template/stats.html
var statsHTML string

//go:embed Template/css/style.css
var styleCSS string

var (
	proxyFile, cnFile, httpFile string
	fileModTime                 = make(map[string]time.Time)
	config                      Config
	db                          *sql.DB
	mu                          sync.Mutex // 用于保护访问日志的并发安全
	tokenTries                  = make(map[string]*TokenTry)
	tokenMu                     sync.RWMutex
)

// 配置结构体
type Config struct {
	PoweredBy      string `json:"poweredBy"`
	Token          string `json:"token"`
	Port           int    `json:"port"`
	ServerLocation string `json:"serverLocation"`
	APIMethod      string `json:"apiMethod"`     // "post", "get", "both"
	MaxTokenTries  int    `json:"maxTokenTries"` // 最大尝试次数
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

// 添加 token 尝试记录结构
type TokenTry struct {
	IP      string
	Count   int
	LastTry time.Time
	Blocked bool
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
	logMessage := fmt.Sprintf(format, v...)
	log.Printf("%s[%s] %s%s\n", color, level, logMessage, colorReset)
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
			Token:          "123456788",
			Port:           8080,
			ServerLocation: "当前测试服务器位于: xxx",
			APIMethod:      "both",
			MaxTokenTries:  5,
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
		logError("无法打开数据库: %v", err)
		os.Exit(1)
	}

	// 创建访问日志表
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS access_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT,
		timestamp DATETIME
	)`)
	if err != nil {
		logError("创建访问日志表失败: %v", err)
		os.Exit(1)
	}

	// 创建路由日志表
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS route_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		route TEXT UNIQUE,
		count INTEGER DEFAULT 0
	)`)
	if err != nil {
		logError("创建路由日志表失败: %v", err)
		os.Exit(1)
	}

	// 清理旧日志
	_, err = db.Exec(`DELETE FROM access_logs WHERE timestamp < DATETIME('now', '-48 hours')`)
	if err != nil {
		logError("删除旧日志失败: %v", err)
	}

	logInfo("数据库初始化完成")
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
		logWarn("请求不存在的文件: %s", filename)
		http.Error(w, "文件不存在", http.StatusNotFound)
		return
	}

	info, err := os.Stat(filename)
	if err != nil {
		logError("文件访问失败: %s, %v", filename, err)
		http.Error(w, "文件无法访问", http.StatusInternalServerError)
		return
	}

	file, err := os.Open(filename)
	if err != nil {
		logError("打开文件失败: %s, %v", filename, err)
		http.Error(w, "文件无法访问", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))

	_, err = io.Copy(w, file)
	if err != nil {
		logError("文件传输失败: %s, %v", filename, err)
		return
	}

	logInfo("文件下载成功: %s", filename)
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

// 添加检查 token 尝试的函数
func checkTokenTry(ip string, token string) bool {
	// 先检查 token 是否正确
	config := loadConfig()
	if token == config.Token {
		return true // token 正确直接返回 true，不记录尝试
	}

	tokenMu.Lock()
	defer tokenMu.Unlock()

	try, exists := tokenTries[ip]

	if !exists {
		tokenTries[ip] = &TokenTry{
			IP:      ip,
			Count:   1, // 第一次错误尝试
			LastTry: time.Now(),
		}
		return true
	}

	// 如果已经被封禁
	if try.Blocked {
		return false
	}

	// 检查是否超过最大尝试次数
	if try.Count >= config.MaxTokenTries {
		try.Blocked = true
		// 更新 IP 黑名单
		addToTokenBlacklist(ip)
		return false
	}

	// 增加尝试次数
	try.Count++
	try.LastTry = time.Now()
	return true
}

// 添加到 token 黑名单
func addToTokenBlacklist(ip string) {
	ipConfig := loadIPControlConfig()
	// 检查是否已在黑名单中
	for _, blackIP := range ipConfig.Blacklist {
		if blackIP == ip {
			return
		}
	}
	ipConfig.Blacklist = append(ipConfig.Blacklist, ip)
	saveIPControlConfig(ipConfig)
	logWarn("IP %s 因多次尝试 token 已被加入黑名单", ip)
}

// 修改 statsHandler 函数
func statsHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	token := r.URL.Query().Get("token")

	// 检查是否被 token 尝试限制
	if !checkTokenTry(clientIP, token) {
		http.Error(w, "403 Forbidden: Too many token attempts", http.StatusForbidden)
		return
	}

	// 基础数据
	data := struct {
		Visitors       int
		LastUpdateTime string
		TopIPs         []string
		TopRoutes      []string
		ShowIPLists    bool
		IPControl      IPControlConfig
		TokenTries     map[string]*TokenTry // 添加 token 尝试记录
	}{
		Visitors:       countVisitorsLast24Hours(),
		LastUpdateTime: toBeijingTime(time.Now()),
		ShowIPLists:    false,
	}

	var err error
	data.TopIPs, err = getTopIPs(15)
	if err != nil {
		log.Printf("查询热门 IP 失败: %v\n", err)
	}

	data.TopRoutes, err = getTopRoutes(15)
	if err != nil {
		log.Printf("查询热门路由失败: %v\n", err)
	}

	config := loadConfig()
	if token == config.Token {
		data.ShowIPLists = true
		data.IPControl = loadIPControlConfig()

		// 添加 token 尝试记录
		tokenMu.RLock()
		data.TokenTries = tokenTries
		tokenMu.RUnlock()
	}

	renderTemplate(w, "stats.html", statsHTML, data)
	logRequest(r, http.StatusOK, int64(len(statsHTML)))
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
		logError("创建文件监视器失败: %v", err)
		return
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
	file, err := os.Open("config.json")
	if err != nil {
		logError("读取 config.json 时出错: %v", err)
		os.Exit(1)
	}
	defer file.Close()

	var cfg Config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		logError("解析 config.json 时出错: %v", err)
		os.Exit(1)
	}
	return cfg
}

// 加载IP控制配置
func loadIPControlConfig() IPControlConfig {
	mu.Lock()
	defer mu.Unlock()

	if _, err := os.Stat("ipcontrol.json"); os.IsNotExist(err) {
		// 创建默认配置
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
		clientIP := getClientIP(r)

		// 检查 token
		token := r.Header.Get("Authorization")
		config := loadConfig()
		if token == config.Token {
			logDebug("IP %s 使用有效 token 访问", clientIP)
			next.ServeHTTP(w, r)
			return
		}

		ipConfig := loadIPControlConfig()
		switch ipConfig.Mode {
		case "blacklist":
			for _, ip := range ipConfig.Blacklist {
				if ip == clientIP {
					logWarn("拦截黑名单 IP 访问: %s", clientIP)
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
				logWarn("拦截非白名单 IP 访问: %s", clientIP)
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

// CSS 路由处理
func cssHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	w.Write([]byte(styleCSS))
}

func main() {
	router := mux.NewRouter()
	router.Use(ipControlMiddleware)

	// 注册 CSS 路由
	router.HandleFunc("/css/style.css", cssHandler)

	// 其他路由注册...
	router.HandleFunc("/", rootHandler)
	router.HandleFunc("/proxy.txt", fileHandler)
	router.HandleFunc("/cn.txt", fileHandler)
	router.HandleFunc("/http.txt", fileHandler)
	router.HandleFunc("/stats", statsHandler)

	// API 路由...

	logInfo("服务已启动，监听端口 :%d", config.Port)
	logInfo("API 方法限制: %s", config.APIMethod)
	ipConfig := loadIPControlConfig()
	logInfo("IP 控制模式: %s", ipConfig.Mode)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), router))
}
