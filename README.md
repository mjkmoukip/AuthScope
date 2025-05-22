# AuthScope - 智能 Web 登录安全评估工具

[![语言](https://img.shields.io/badge/language-Python-blue.svg)](https://www.python.org/)
[![框架](https://img.shields.io/badge/framework-Playwright-brightgreen.svg)](https://playwright.dev/)
[![GitHub last commit](https://img.shields.io/github/last-commit/mjkmoukip/AuthScope.svg)](https://github.com/你的用户名/AuthScope/commits/main)

**AuthScope** 是一款专为现代动态 Web 应用（如 SPA 单页应用）设计的后台弱口令自动化检测工具。它通过智能分析登录页面 DOM、模拟用户交互、处理验证码（集成 ddddocr）以及精细化判断登录结果，致力于解决传统工具在识别动态生成登录界面、处理复杂登录逻辑以及准确判断登录结果方面的不足。

## 🚀 项目背景与目标

随着 Web 技术的发展，越来越多的网站采用前后端分离和动态加载技术，这给传统的基于固定规则的弱口令扫描工具带来了挑战。AuthScope 的目标是：

1.  **动态适应**：能够有效识别和处理由 JavaScript 动态生成的登录表单元素。
2.  **智能交互**：模拟真实用户操作，包括填写表单、点击按钮、处理验证码等。
3.  **精准判断**：通过分析登录后的页面变化、网络请求响应及弹窗信息，更准确地判断登录尝试是否成功。
4.  **并发高效**：利用异步IO和多Worker机制，提高扫描效率。
5.  **易于扩展**：模块化设计，方便未来添加新的识别策略或攻击模块。

本项目作为毕业设计，旨在探索和实践上述目标，为 Web 安全评估提供一款更现代化、更有效的自动化工具。

## ✨ 核心特性

*   **动态登录表单分析**：基于元素属性、ARIA Role 及文本内容智能定位用户名、密码输入框、提交按钮及验证码相关元素。
*   **异步并发扫描**：基于 `asyncio` 和 Playwright 构建，支持多 Worker 并发处理任务队列，显著提升扫描速度。
*   **智能登录尝试与结果判断**：精细化处理登录过程中的各种情况（如弹窗、页面跳转、网络请求），并根据预设关键字分析登录结果（成功、密码错误、用户不存在、验证码错误、账户锁定等）。
*   **验证码识别支持**：集成 `ddddocr` 库，能够自动识别并尝试填充图片验证码。
*   **灵活的凭证管理**：支持从文件加载用户名字典、密码字典，并可配置常见组合及万能密码优先尝试。
*   **可配置的浏览器行为**：通过配置文件控制浏览器类型、无头模式、代理、User-Agent、视口大小等。
*   **详细的报告输出**：将扫描结果（包括成功凭证、尝试详情、错误信息）输出到控制台和本地文件。



## ⚙️ 安装与环境配置 

1. **克隆仓库**: 

2. **安装依赖**:

   ```bash
   pip install -r requirements.txt
   ```

3. **安装 Playwright 浏览器驱动**:
   AuthScope 默认使用 Chromium。
   ```bash
   playwright install chromium
   ```
   **配置 (可选)**:

   *   主要的配置文件位于 `config/config.yaml`。你可以在此调整浏览器设置、并发数、超时时间、字典路径等。 (目前只有部分配置可生效)

## 🚀 如何使用

确保你已经完成了安装和环境配置。

*   **扫描单个 URL**:
    
    ```bash
    python main.py -u https://example.com/login
    ```
    
*   **从文件批量扫描 URL**:
    创建一个文本文件 (例如 `urls.txt`)，每行包含一个 URL。
    ```
    https://example.com/login1
    https://another.example.org/signin
    http://localhost:8080/admin
    ```
    

扫描结果将输出到控制台，并默认保存在 `results/scan_report.txt` 文件中。

## 🔧 配置文件 (`config/config.yaml`)

...

## 💡 未来展望

*   训练零分类模型并为项目加入数据库，解决登录判断模块中，单一关键字带来的误报问题。

## 📜 许可证

本项目采用 [MIT 许可证](LICENSE) 。

## ⚠️ 免责声明

**本工具仅供授权渗透测试和安全研究使用。请勿用于非法目的。任何未经授权的测试行为均可能触犯法律，使用者需自行承担所有相关法律责任。开发者不对此工具的任何滥用行为负责。**

