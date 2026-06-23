
<h4 align="center">红队资产存活探测与重点攻击系统指纹识别工具</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Author-sangnigege-da282a">
  <img src="https://img.shields.io/badge/Language-Python%203.10+-da282a">
  <img src="https://img.shields.io/badge/Version-V6.0-da282a">
  <img src="https://img.shields.io/badge/Rules-16858-da282a">
  <img src="https://img.shields.io/badge/Products-11945-da282a">
</p>

---

## 项目简介

Finger 是一款面向红队的资产指纹探测工具，在大量资产中快速识别重点攻击系统（OA、CMS、框架、防火墙、路由器、CDN 等），协助渗透测试人员快速定位高价值目标。

本分支在原项目 V5.1 基础上进行了大量优化：规则质量提升、置信度引擎重写、Server 版本提取、默认口令标注、规则审计、架构统一等。

### 核心能力

- **存活探测** — 并发 HTTP 扫描，自动处理 URL 格式异常
- **指纹识别** — 16,858 条规则，覆盖 11,945 产品（CMS、OA、框架、防火墙、路由器、摄像头、CDN 等）
- **智能置信度** — 算法自动计算置信度，根据匹配位置/命中率/关键词质量分级着色
- **CDN 检测** — 三层检测：多 IP 判定 + CIDR 范围匹配 + 响应头特征
- **IP 归属地** — 基于 ip2region 数据库，自动获取 IP 地理位置和运营商
- **资产收集** — 支持 FOFA / 360 Quake API 资产搜集
- **库模式调用** — `from lib.finger import Finger` 可被其他工具直接引用
- **规则质量审计** — `--audit` 自动检测潜在误报规则
- **Server 版本提取** — 自动从 Server 头提取 nginx/Apache/IIS 等版本号
- **默认口令** — 输出标注已知产品的默认口令

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

# 启用规则质量审计
python Finger.py -f targets.txt --audit

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
| `--audit` | 🆕 启用规则质量审计，扫描后生成审计报告 |

支持的 URL 格式：`www.baidu.com`、`127.0.0.1`、`http://www.baidu.com` 均可自动处理。

支持的 IP 格式：`192.168.1.1`、`192.168.1.0/24`、`192.168.1.10-192.168.1.50`。

### 输出列说明

| 列 | 说明 |
|------|------|
| Url | 目标 URL |
| Title | 页面标题 |
| CMS | 识别到的产品指纹（**红色** ≥80分，**黄色** ≥50分） |
| Confidence | 置信度分数 (0-100)，算法自动计算 |
| Version | 产品版本号 / 设备型号 |
| Server | 原始 Server 响应头 |
| Status | HTTP 状态码 |
| Size | 响应体大小 |
| IP | IP 地址 |
| Address | IP 归属地（需 --geo） |
| ISP | 运营商（需 --geo） |
| DefaultCreds | 🆕 已知默认口令 |

---

## 配置说明

编辑 `config/settings.py`：

```python
# 线程数，默认 30
threads = 30

# HTTP请求超时（秒），默认 5
timeout = 5

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
    "location": "title",
    "keyword": ["Apache Shiro", "apache shiro quickstart"],
    "logic": "and"
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
| `url` | 🆕 URL 路径匹配（dirsearch 联动友好） |

### 置信度算法（V6.0）

置信度不再由规则预设，而是从匹配过程**自动推导**：

| 因素 | 影响 |
|------|------|
| 匹配位置 | title/url +25, header +10, body +0 |
| 匹配方法 | faviconhash → 直接 95 分 |
| AND 多关键词 | +15（全部命中 → 极低FP） |
| OR 命中率 | 按 `命中数/总关键词` 比例加分 |
| 短通用词 | 如 "php" "asp" ≤3字符 → -20 |
| HTML 标签 | 如 `<span>` → -15 |
| URL 路径在 body | 短路径在 body 中出现 → -10 |
| Server 交叉校验 | 预期 Server 不匹配 → -20 |

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
- `verify=False` 跳过 SSL 证书验证（主页 **和** favicon）

---

## 架构

```
Finger.py          CLI 入口 → Finger 类统一引擎
lib/finger.py      扫描引擎（CLI + 库模式共用）
lib/identify.py    指纹匹配 + 置信度计算
lib/output.py      xlsx/json 输出
lib/audit.py       🆕 规则质量审计
lib/options.py     URL 预处理
lib/checkenv.py    环境检测
config/settings.py 配置文件
library/           指纹库 + 默认口令库 + CDN/IP数据
```

---

## V6.0 改进说明

> 本仓库 (sangnigege/Finger) 基于上游 EASY233/Finger V5.1 开发，计划合回上游。

### 规则优化
- **删除 32 个通用误报关键词**（`body`、`/login`、`download`、`self.location`、`username` 等）
- **新增 ~500 条指纹规则**（OA/ERP/打印机/安全设备/AI 平台等 60+ 类别）
- **URL 路径匹配** 新增 130 条 `location: url` 规则
- **产品型号提取** 支持 HP/海康/Dell/Canon/Lenovo 等硬件型号
- **Server 交叉校验** 对 17 个易误报产品配置预期 Server 头

### 引擎改进
- **置信度算法重写** — 从人工标注改为自动推导（位置/命中率/关键词质量）
- **favicon SSL 修复** — favicon 请求增加 `verify=False`
- **Server 版本自动提取** — 从 Server 头提取 nginx/Apache/IIS 等版本
- **超时优化** — 默认从 10s 降为 5s，扫描速度提升 ~40%

### 输出增强
- **默认口令列** — xlsx 新增 `DefaultCreds` 列，覆盖 34 个常见产品
- **置信度分级着色** — ≥80 红色（高置信），50-79 黄色（中置信）
- **JSON 中文输出** — 修复 `ensure_ascii=False`

### 质量保障
- **规则审计** — `--audit` 四维自动检测（Server 多样性/404命中率/命中率异常/关键词质量）
- **架构统一** — `req.py` 废弃，CLI + 库模式共用 `Finger` 类

### 性能
- 6000 URL 扫描从 ~21 分钟降至 ~12 分钟
- favicon SSL 错误从 100+ 降至 2
- favicon 总失败率 ~1.6%

---

## 更新日志

### V6.0（本仓库, sangnigege/Finger）

- **规则库**：16,359→16,858 条规则，新增 OA/ERP/打印机/AI/安全等 60+ 类别，覆盖 11,945 产品
- **置信度引擎**：重写为算法自动计算（位置/命中率/关键词质量），零维护成本
- **URL 路径匹配**：新增 `location: url`（130 条规则），与 dirsearch 联动
- **Server 版本提取**：自动提取 nginx/Apache/IIS/PHP 等 10+ 种 Server 版本号
- **型号提取**：`model_regex` 支持 HP/海康/Dell/Canon/Lenovo 等硬件型号
- **默认口令**：34 产品默认口令独立列标注
- **规则审计**：`--audit` 四维自动检测（Server 多样性/404 命中率/命中率异常/关键词质量）
- **架构统一**：CLI + 库模式共用 `Finger` 类，`req.py` 废弃
- **质量修复**：删除 32 个通用误报关键词（`body`、`/login`、`download` 等），favicon SSL 修复
- **性能优化**：默认超时 10→5s，扫描速度提升 ~40%
- **输出增强**：置信度分级着色（≥80 红/≥50 黄），JSON 中文修复
- **指纹库**：合并 17 个来源（含 EHole + MUKI），254K 原始规则去重清洗

### V5.1（2022-03，上游 EASY233/Finger）

- 优化输出，修复 FOFA API bug

### V5.0（2021-09，上游 EASY233/Finger）

- xlsx/json 输出，IP 归属地，FOFA/Quake API 集成

### V5.1（2022-03）

- 优化输出，修复 FOFA API bug

### V5.0（2021-09）

- xlsx/json 输出，IP 归属地，FOFA/Quake API 集成

---

## 感谢

在开发过程中实际参考和引用了以下优秀开源项目：

- [Finger](https://github.com/EASY233/Finger) — 本项目上游（V5.1），由 EASY 开发
- [EHole(棱洞)](https://github.com/EdgeSecurityTeam/EHole) — 指纹识别思路与规则格式
- [ip2region](https://github.com/lionsoul2014/ip2region) — IP 归属地数据库与查询引擎
- [ObserverWard](https://github.com/0x727/ObserverWard) — 指纹库参考
- [FingerprintHub](https://github.com/0x727/FingerprintHub) — ObserverWard 指纹库
