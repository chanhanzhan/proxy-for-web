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
	PoweredBy      string `json:"poweredBy"`
	Port           int    `json:"port"`
	ServerLocation string `json:"serverLocation"`
}

// 访问日志结构体
type AccessLog struct {
	IP        string
	Timestamp time.Time
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
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("读取 config.json 时出错: %v\n", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("解析 config.json 时出错: %v\n", err)
	}
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

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS access_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT,
		timestamp DATETIME
	)`)
	if err != nil {
		log.Fatalf("创建表失败: %v\n", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS route_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		route TEXT,
		count INTEGER
	)`)
	if err != nil {
		log.Fatalf("创建表失败: %v\n", err)
	}

	_, err = db.Exec(`DELETE FROM access_logs WHERE timestamp < DATETIME('now', '-48 hours')`)
	if err != nil {
		log.Fatalf("删除旧日志失败: %v\n", err)
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

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/proxy.txt", fileHandler)
	http.HandleFunc("/cn.txt", fileHandler)
	http.HandleFunc("/http.txt", fileHandler)
	http.HandleFunc("/stats", statsHandler)

	log.Printf("服务已启动，监听端口 :%d\n", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
