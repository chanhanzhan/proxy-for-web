# 代理池服务 🚀

一个功能强大的代理池服务，支持代理文件管理、访问统计、IP 控制等功能。

<!-- 新增部分：新版功能说明 -->
## 新版功能介绍 🔥

本版本在原有功能基础上新增和改进了以下特性：
- **自动文件更新**：通过文件监听机制，实时监控并自动应用代理文件的变更。
- **Token 尝试次数限制**：对 Token 验证尝试次数进行限制，超过最大次数后自动封禁恶意 IP。
- **动态鉴权 Key 管理**：支持在运行中动态添加和删除鉴权 key，无需重启服务即可生效。
- **改进的日志系统**：终端日志支持彩色输出，区分 INFO、WARN、ERROR、DEBUG 等信息。
- **丰富访问统计**：提供 24 小时访问人数统计、热门 IP 和热门路由分析，助您快速掌握业务情况。

## 功能特点 ✨

- 🌈 美观的彩虹渐变界面
- 📊 实时访问统计
- 🔒 IP 黑白名单控制
- 🎫 Token 访问控制
- 📝 详细的访问日志
- 🔄 文件自动更新
- 🎨 彩色终端日志输出
- 📱 响应式设计
- 🛡️ Token 尝试次数限制
- ⚡ 高性能文件服务
- 📈 24小时访问统计
- 🔍 热门 IP 和路由分析

## 项目目录结构 📂
```
├── config.json           # 主配置文件
├── ipcontrol.json       # IP控制配置文件
├── data.db              # SQLite数据库文件
├── go.mod               # Go模块文件
├── go.sum               # Go依赖校验文件
├── web.go               # 主程序文件
├── LICENSE              # 许可证文件
├── README.md            # 项目说明文件
└── Template/
    ├── index.html      # 主页模板
    ├── stats.html      # 统计页面模板
    └── css/
        └── style.css   # 共享样式文件
```

## 快速开始 🚀

### 安装
```bash
git clone https://github.com/chanhanzhan/proxy-for-web.git
cd proxy-for-web
go mod tidy
```

### 运行
```bash
go run web.go
```

默认监听端口为 8080，可以通过配置文件修改。

## 配置文件 ⚙️

### config.json
```json
{
    "poweredBy": "@YourName",        // 服务提供者标识
    "token": "your_token",           // API 认证令牌
    "port": 8080,                    // 服务器端口
    "maxTokenTries": 5,              // token尝试最大次数
    "serverLocation": "服务器位置描述", // 服务器位置说明
    "apiMethod": "both"              // API方法限制
}
```

### ipcontrol.json
```json
{
    "mode": "none",                  // IP控制模式：none, blacklist, whitelist
    "blacklist": [],                 // IP黑名单列表
    "whitelist": ["127.0.0.1"]      // IP白名单列表
}
```

## IP 控制模式 🛡️

- `none`: 不进行 IP 控制
- `blacklist`: 黑名单模式，禁止特定 IP 访问
- `whitelist`: 白名单模式，只允许特定 IP 访问

## API 接口说明 📡

所有 API 接口都需要在请求头中携带 Authorization 令牌。
携带有效 token 的请求将跳过 IP 控制检查。

### 统计页面
```
GET /stats?token=your_token
```

### 代理文件访问
```
GET /proxy.txt
GET /cn.txt
GET /http.txt
```

### 白名单管理

#### 添加 IP 到白名单
```bash
# POST 方法
curl -X POST 'http://localhost:8080/api/whitelist/add' \
-H 'Authorization: your_token' \
-H 'Content-Type: application/json' \
-d '{"ip": "192.168.1.1"}'

# GET 方法
curl -X GET 'http://localhost:8080/api/whitelist/add?ip=192.168.1.1' \
-H 'Authorization: your_token'
```

#### 从白名单移除 IP
```bash
# POST 方法
curl -X POST 'http://localhost:8080/api/whitelist/remove' \
-H 'Authorization: your_token' \
-H 'Content-Type: application/json' \
-d '{"ip": "192.168.1.1"}'

# GET 方法
curl -X GET 'http://localhost:8080/api/whitelist/remove?ip=192.168.1.1' \
-H 'Authorization: your_token'
```

### 黑名单管理

#### 添加 IP 到黑名单
```bash
# POST 方法
curl -X POST 'http://localhost:8080/api/blacklist/add' \
-H 'Authorization: your_token' \
-H 'Content-Type: application/json' \
-d '{"ip": "192.168.1.1"}'

# GET 方法
curl -X GET 'http://localhost:8080/api/blacklist/add?ip=192.168.1.1' \
-H 'Authorization: your_token'
```

#### 从黑名单移除 IP
```bash
# POST 方法
curl -X POST 'http://localhost:8080/api/blacklist/remove' \
-H 'Authorization: your_token' \
-H 'Content-Type: application/json' \
-d '{"ip": "192.168.1.1"}'

# GET 方法
curl -X GET 'http://localhost:8080/api/blacklist/remove?ip=192.168.1.1' \
-H 'Authorization: your_token'
```

### API 响应格式
```json
{
    "success": true,           // 操作是否成功
    "message": "操作说明信息"    // 详细的操作结果说明
}
```

### 常见响应状态码
- 200: 操作成功
- 400: 请求参数错误
- 401: 未授权（token 无效）
- 403: IP 被限制访问/Token尝试次数超限
- 405: 请求方法不允许
- 500: 服务器内部错误

## 安全特性 🔐

- Token 访问控制
- Token 尝试次数限制（默认 5 次）
- 自动封禁恶意 IP
- IP 黑白名单控制
- 访问日志记录
- XSS 防护
- 文件访问限制

## 日志系统 📝

支持彩色终端输出，包括以下级别：
- INFO (绿色) - 普通信息
- ERROR (红色) - 错误信息
- WARN (黄色) - 警告信息
- DEBUG (青色) - 调试信息
- API (多彩) - API访问日志

## 数据库 💾

使用 SQLite 存储访问日志和统计数据：
- 访问记录表 (access_logs)
  - IP 地址
  - 访问时间戳
- 路由统计表 (route_logs)
  - 路由路径
  - 访问次数

## 统计功能 📊

- 24小时访问人数统计
- 热门 IP 统计（TOP 15）
- 热门路由统计（TOP 15）
- Token 尝试记录
- IP 控制配置展示

## 部署要求 🔧

- Go 1.16 或更高版本
- SQLite 支持
- 现代浏览器（支持 CSS Grid 和 Flexbox）

## 贡献 🤝

欢迎提交 Issue 和 Pull Request！

## 许可证 📄

Apache License 2.0 - 查看 [LICENSE](LICENSE) 文件了解更多信息。
