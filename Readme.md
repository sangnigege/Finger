

<h4 align="center">红队资产存活探测与重点攻击系统指纹识别工具</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Author-sangnigege-da282a">
  <img src="https://img.shields.io/badge/Language-Python%203.10+-da282a">
  <img src="https://img.shields.io/badge/Version-V6.0-da282a">
  <img src="https://img.shields.io/badge/Rules-16347-da282a">
</p>

---

## 项目简介

Finger 是一款面向红队的资产指纹探测工具，在大量资产中快速识别重点攻击系统（OA、CMS、框架、防火墙、路由器、CDN 等），协助渗透测试人员快速定位高价值目标。


### 核心能力

- **存活探测** — 并发 HTTP 扫描，自动处理 URL 格式异常
- **指纹识别** — 上万条规则，覆盖 CMS、OA、框架、防火墙、路由器、摄像头、CDN 等
- **CDN 检测** — 三层检测：多 IP 判定 + CIDR 范围匹配 + 响应头特征
- **IP 归属地** — 基于 ip2region 数据库，自动获取 IP 地理位置和运营商
- **资产收集** — 支持 FOFA / 360 Quake API 资产搜集
- **库模式调用** — `from lib.finger import Finger` 可被其他工具直接引用

---

## 快速开始

### 环境要求

- Python 3.10+
- Linux / macOS / Windows

### 安装

```bash
git clone https://github.com/sangnigege/Finger.git
cd Finger
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 使用

```bash
# 单个 URL 指纹识别
python Finger.py -u http://example.com

# 批量 URL 扫描
python Finger.py -f targets.txt

# 指定输出格式 (json / xlsx，默认 xlsx)
python Finger.py -f targets.txt -o json

# IP 资产收集（自动调 FOFA 获取 web 资产）
python Finger.py -i 192.168.1.0/24

# FOFA / Quake 关键词搜索
python Finger.py -fofa
python Finger.py -quake
```

### 库模式

```python
from lib.finger import Finger

f = Finger(threads=30)
results, filepath = f.scan_and_save(
    ['http://target1.com', 'http://target2.com'],
    fmt='xlsx'
)
for r in results:
    print(f"{r['url']} → {r['cms']} [{r['confidence']}]")
```

---

## 参数说明

| 参数 | 说明 |
|------|------|
| `-u URL` | 单个 URL 指纹识别 |
| `-f FILE` | 批量 URL 文件 |
| `-i IP` | IP/IP段/IP范围（自动调 FOFA 获取 web 资产） |
| `-if FILE` | IP 文件 |
| `-fofa` | 交互式 FOFA 关键词搜索 |
| `-quake` | 交互式 360 Quake 关键词搜索 |
| `-o FORMAT` | 输出格式：`json` / `xlsx`（默认 xlsx） |
| `--proxy URL` | HTTP/SOCKS5 代理 |
| `--cdn` | 启用 CDN 检测（默认关闭） |
| `--geo` | 启用 IP 归属地查询（默认关闭） |

支持的 URL 格式：`www.baidu.com`、`127.0.0.1`、`http://www.baidu.com` 均可自动处理。

支持的 IP 格式：`192.168.1.1`、`192.168.1.0/24`、`192.168.1.10-192.168.1.50`。

---

## 配置说明

编辑 `config/settings.py`：

```python
# 线程数，默认 30
threads = 30

# FOFA API 配置
Fofa_email = ""
Fofa_key = ""
Fofa_Size = 100       # 普通会员 100，高级会员 10000

# 360 Quake API 配置（每月免费 3000 条）
QuakeKey = ""

# 是否启动时在线更新指纹库（默认关闭）
FingerPrint_Update = False
```

---

## 指纹识别

### 规则格式

```json
{
    "cms": "Shiro",
    "method": "keyword",
    "location": "header",
    "keyword": ["rememberMe=", "=deleteMe", "shiroCookie"],
    "logic": "or",
    "confidence": 100
}
```

### 识别方式

| method | 说明 | 精度 | 示例 |
|--------|------|------|------|
| `keyword` | 关键词匹配（支持 AND/OR 逻辑） | header/title 精准，body 取决于关键词质量 | `"keyword": ["Swagger UI"]` |
| `faviconhash` | favicon 图标 hash 匹配 | 极高（几乎零误报） | `"keyword": ["81586312"]` |
| `regula` | 正则表达式匹配 | 取决于正则质量 | `"keyword": ["Apache/([\\d.]+)"]` |

### 匹配位置

| location | 说明 |
|----------|------|
| `header` | HTTP 响应头（多格式兼容，含 EHole 格式） |
| `title` | 页面 `<title>` 标签 |
| `body` | 页面 HTML 全文 |

### 匹配逻辑

- 同名 CMS 去重后全部输出，按置信度降序排列
- 规则可指定 `confidence`（0-100），默认 100
- 双 favicon hash（EHole + FOFA 兼容）

### 规则规模

| 类型 | 数量 |
|------|------|
| keyword（关键词） | 15,750 |
| faviconhash（图标哈希） | 596 |
| regula（正则） | 1 |
| **总计** | **16347** |
| 覆盖产品数 | 11,617 |

---

## CDN 检测

三层检测机制：

| 层级 | 方式 | 说明 |
|------|------|------|
| ① DNS 多 IP | 解析到 ≥2 个 IP | 多数 CDN 返回多个边缘节点 IP |
| ② CIDR 匹配 | 540 条已知 CDN IP 段 | 单 IP 时与已知 CDN IP 范围对比 |
| ③ 响应头特征 | 16 个 CDN 专属响应头 | Cloudflare/Fastly/CloudFront/Akamai 等 |

三层之间短路判断，零额外发包。

---

## WAF 隐匿

- 每个目标最多 2 次发包（主页 + favicon）
- 请求头包含 `Sec-Fetch-*` 系列，与 Chrome 浏览器一致
- favicon 请求使用正确的 `Accept: image/*` 头
- UA 池为 2025 年 Chrome 131 / Firefox 135
- 不发送 Cookie（已移除 `rememberMe=test`）
- `verify=False` 跳过 SSL 证书验证


---


## 更新日志

### V6.0（2026-06）

- **指纹库**：合并 17 个来源（含 EHole + MUKI），254K 原始规则去重清洗 → 16,347 条，覆盖 11,617 产品
- **匹配引擎**：keyword + faviconhash + regula 三种方式，OR/AND 逻辑，双 hash 兼容（EHole + FOFA）
- **CMS 名归一化**：统一大小写/空格/横线变体 + 同名产品 OR 合并
- **版本号提取**：110 条 version_regex 覆盖 80 产品
- **CDN 检测**：三层检测 + 16 种响应头特征（默认关闭，`--cdn` 开启）
- **WAF 隐匿**：添加 `Sec-Fetch-*` 浏览器头，favicon 请求修正 Accept
- **安全修复**：移除 `rememberMe=test` Shiro Cookie（自曝扫描器特征）
- **Bug 修复**：CaseInsensitiveDict 兼容、ip2region 文件泄漏、logger 未定义
- **库模式**：`from lib.finger import Finger` 可供其他工具直接引用
- **跨平台**：修复 Python 3.10-3.13 兼容性，移除 Windows 专用依赖
- **ip2region 升级**：v1 → v3.16.0 xdb 格式（更小 7MB vs 11MB，更准，2025年数据）
- **依赖精简**：12→4 个直接依赖，移除 lxml/urllib3/pyreadline/beautifulsoup4 等冗余，HTML解析改用正则
- **输出增强**：XLSX 按置信度红/橙着色，新增 Confidence/Version 列

### V5.1（2022-03）

- 优化输出，修复 FOFA API bug

### V5.0（2021-09）

- xlsx/json 输出，IP 归属地，FOFA/Quake API 集成

---

## 感谢

在开发过程中实际参考和引用了以下优秀开源项目：

- [Finger](https://github.com/EASY233/Finger) — 本项目上游，由 EASY 开发的 V5.1 版本
- [EHole(棱洞)](https://github.com/EdgeSecurityTeam/EHole) — 指纹识别思路与规则格式
- [ip2region](https://github.com/lionsoul2014/ip2region) — IP 归属地数据库与查询引擎

