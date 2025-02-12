# proxy-for-web 🚀

## 项目介绍 📖
该项目是一个基于 Go 语言的 Web 应用程序，提供文件访问和统计功能。用户可以通过 Web 界面查看文件内容和访问统计信息。

## 功能列表 ✨
- **文件访问**：用户可以访问特定的文件。
- **访问日志**：记录用户的访问日志，包括 IP 地址、访问时间、请求路径等信息。
- **访问统计**：统计过去 24 小时的访问人数、热门 IP 和热门路由。

## 项目特性 🌟
- **高性能**：基于 Go 语言的高并发处理能力。
- **易于部署**：简单的配置和部署步骤。
- **实时监控**：实时监控文件变化并更新统计信息。
- **安全性**：防止非法操作和攻击，确保系统的安全性。

## 项目文件说明 📂
- `web.go`：主程序文件，包含服务器启动和路由处理逻辑。
- `config.json`：配置文件，包含服务器配置参数。
- `Template/index.html`：HTML 模板文件，用于渲染主页。
- `data.db`：SQLite 数据库文件，用于存储访问日志和路由日志。

## 项目目录结构 🗂
```
C:\Users\chanh\Desktop\web
│   config.json          # 配置文件，包含服务器配置参数
│   go.mod               # Go 模块文件，定义依赖项
│   go.sum               # Go 模块校验和文件，记录依赖项的版本信息
│   README.md            # 项目说明文件
│   web.go               # 主程序文件，包含服务器启动和路由处理逻辑
│
└───Template
        index.html       # HTML 模板文件，用于渲染主页
```

## 部署编译环境 🛠
1. **安装 Go 语言环境**：
    请参考 [Go 官方文档](https://golang.org/doc/install) 进行安装。

2. **安装依赖**：
    ```bash
    go mod tidy
    ```

## 部署步骤 🚀
1. **克隆项目代码**：
    ```bash
    git clone https://github.com/chanhanzhan/proxy-for-web.git
    ```
2. **进入项目目录**：
    ```bash
    cd proxy-for-web
    ```
3. **安装依赖**：
    ```bash
    go mod tidy
    ```
4. **启动项目**：
    ```bash
    go run web.go
    ```

## 贡献 🤝
如果你想为这个项目做出贡献，请提交 pull request 或者报告问题。

## 许可证 📄
该项目使用 Apache 许可证。
