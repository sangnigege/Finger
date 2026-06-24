#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Finger 库接口 — 可被 dirsearch_bypass403 等工具直接 import 使用

用法:
    from lib.finger import Finger
    f = Finger(threads=30)
    results = f.scan(['http://target1.com', 'http://target2.com'])
    # results 是 dict 列表，可直接使用或传入 Output 导出
"""
import os
import random
import base64
import hashlib
import json
import requests
import mmh3
import urllib3
import xlsxwriter
from urllib.parse import urlsplit, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import re
from config.data import path, logging, Extra
from config import settings
from lib.identify import Identify
from lib.ip_factory import IPFactory

urllib3.disable_warnings()


class Finger:
    """Finger 指纹识别器 — 库入口"""

    def __init__(self, threads=30):
        self.threads = threads
        self._init_paths()
        self.identify = Identify()
        self.ip_factory = IPFactory()

    def _init_paths(self):
        """确保路径已初始化（兼容直接 import 而非 CLI 入口）"""
        if not hasattr(path, 'library') or not path.library:
            root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
            path.home = root
            path.library = os.path.join(root, 'library')

    # ── 公开 API ──────────────────────────

    def scan(self, urls, timeout=None):
        """扫描 URL 列表，返回识别结果列表。

        Args:
            urls: URL 字符串列表
            timeout: HTTP 请求超时（秒），None 则使用 settings.timeout

        Returns:
            list[dict]
        """
        if timeout is None:
            timeout = getattr(settings, 'timeout', 10)
        results = []
        errors = []
        unique_urls = list(set(urls))

        pool = ThreadPoolExecutor(self.threads)
        try:
            futures = {pool.submit(self._scan_one, url, timeout): url for url in unique_urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    if result: results.append(result)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    errors.append({"url": url, "cms": "-", "title": str(e),
                        "status": "-", "Server": "-", "size": "-",
                        "iscdn": "-", "ip": "-", "address": "-",
                        "isp": "-", "confidence": 0, "version": "-"})
        except KeyboardInterrupt:
            pool.shutdown(wait=False, cancel_futures=True)
            logging.error("用户强制中止!")
        finally:
            pool.shutdown(wait=False)

        # 有 CMS 的结果优先排在前面
        results.sort(key=lambda r: (r.get("confidence", 0), r.get("cms") != ""),
                     reverse=True)
        return results + errors

    def scan_and_save(self, urls, output_dir=None, fmt="xlsx", timeout=None):
        """扫描并保存结果到文件。

        Args:
            urls: URL 列表
            output_dir: 输出目录，默认 library 同级的 output/
            fmt: 输出格式 "xlsx" 或 "json"
            timeout: HTTP 请求超时

        Returns:
            (results, filepath): 结果列表和输出文件路径
        """
        results = self.scan(urls, timeout=timeout)

        if output_dir is None:
            output_dir = os.path.join(path.home, 'output')
        os.makedirs(output_dir, exist_ok=True)

        import time as _time
        ts = _time.strftime("%Y%m%d%H%M%S", _time.localtime())

        if fmt == "json":
            filepath = os.path.join(output_dir, f"{ts}.json")
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
        else:
            filepath = self._save_xlsx(results, output_dir, ts)

        logging.success(f"结果已保存: {filepath}")
        return results, filepath

    # ── 内部实现 ──────────────────────────

    def _scan_one(self, url, timeout):
        """扫描单个 URL，返回结果 dict"""
        try:
            with requests.get(
                url, timeout=timeout,
                headers=self._get_headers(),
                verify=False,
                allow_redirects=True,
                stream=True,
                proxies=settings.get_proxies(),
            ) as resp:
                return self._process_response(url, resp)
        except Exception as e:
            return {
                "url": url, "cms": "", "confidence": 0, "version": "-",
                "title": str(e), "status": "-", "Server": "-",
                "size": "-", "iscdn": "-", "ip": "-",
                "address": "-", "isp": "-",
            }

    def _process_response(self, url, response):
        """解析 HTTP 响应，做指纹匹配"""
        content_length = int(response.headers.get("content-length", 1000))

        if content_length > 100000:
            html = ""
            size = content_length
        else:
            response.encoding = (
                response.apparent_encoding
                if response.encoding == 'ISO-8859-1'
                else response.encoding
            )
            response.encoding = "utf-8" if response.encoding is None else response.encoding
            html = response.content.decode(response.encoding, "ignore")
            size = len(html)

        title = self._get_title(html)
        server = response.headers.get("Server", "")
        server = "" if len(server) > 50 else server

        # favicon 正则提取
        favicon_url_hint = None
        if html:
            parsed = urlsplit(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            favicon_url_hint = self._find_favicon_href(html, base)
        faviconhash = self._get_faviconhash(url, favicon_url_hint)

        # CDN/IP (默认关闭，--cdn 开启)
        if Extra.cdn:
            try:
                iscdn, iplist = self.ip_factory.factory(url)
                if iscdn == 0 and self.ip_factory.check_cdn_headers(response.headers):
                    iscdn = 1
                iplist_str = ','.join(set(iplist))
            except Exception:
                iscdn, iplist_str = 0, ""
        else:
            iscdn, iplist_str = 0, ""

        # 指纹匹配
        datas = {
            "url": url, "title": title, "body": html,
            "status": response.status_code, "Server": server,
            "size": size, "header": response.headers,
            "faviconhash": faviconhash, "iscdn": iscdn,
            "ip": iplist_str, "address": "", "isp": "",
        }
        match_info = self.identify.match(datas)

        # 控制台实时输出（贴近 V5.1，增加置信度）
        if match_info["cms"]:
            from config.color import color
            logging.success("{0} {1} {2} {4} {3}  [{5}]".format(
                color.green(match_info['cms']),
                color.blue(server),
                str(title)[:50],
                color.yellow(str(response.status_code)),
                url,
                color.cyan(str(match_info['confidence'])),
            ))

        # Server header 版本兜底提取
        version = match_info["version"] if match_info["version"] != "-" else ""
        if not version and server:
            version = self._extract_server_version(server)
        if version:
            version = version.strip()

        return {
            "url": url,
            "cms": match_info["cms"],
            "confidence": match_info["confidence"],
            "version": version or "-",
            "title": title,
            "status": response.status_code,
            "Server": server,
            "size": size,
            "iscdn": iscdn,
            "ip": iplist_str,
            "address": "",
            "isp": "",
            "faviconhash": faviconhash,
        }

    # ── HTTP 请求工具 ──────────────────────

    def _get_headers(self):
        ua = random.choice(settings.user_agents)
        return {
            'Accept': 'text/html,application/xhtml+xml,'
                      'application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'User-Agent': ua,
        }

    # ── favicon ───────────────────────────

    def _get_faviconhash(self, url, favicon_url_hint=None):
        favicon_url = url
        try:
            parsed = urlsplit(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            target = favicon_url_hint if favicon_url_hint else urljoin(base, "favicon.ico")
            h = self._get_headers()
            h['Accept'] = 'image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5'
            h['Sec-Fetch-Dest'] = 'image'
            h['Sec-Fetch-Mode'] = 'no-cors'
            h['Sec-Fetch-Site'] = 'same-origin'
            h.pop('Upgrade-Insecure-Requests', None)
            h.pop('Sec-Fetch-User', None)
            resp = requests.get(target, headers=h, timeout=3, verify=False, proxies=settings.get_proxies())
            raw = resp.content
            return {'ehole': mmh3.hash(base64.encodebytes(raw)),
                    'fofa': mmh3.hash(base64.b64encode(raw)),
                    'md5': hashlib.md5(raw).hexdigest()}
        except Exception as e:
            logging.warning(f"favicon 获取失败: {favicon_url} → {e}")
            return {'ehole': 0, 'fofa': 0}

    def _find_favicon_href(self, html, base_url):
        """正则提取 favicon 路径，兼容 href/rel 任意顺序"""
        try:
            # 方案1: 提取 link[rel=icon] 中的 href
            m = re.search(
                r'<link[^>]+?rel=["\'](?:icon|shortcut icon|apple-touch-icon)["\'][^>]*?href=["\']([^"\']+)["\']',
                html, re.I)
            if m and not m.group(1).startswith('data:'):
                return urljoin(base_url, m.group(1))
            # 方案2: rel 和 href 顺序相反
            m = re.search(
                r'<link[^>]+?href=["\']([^"\']+)["\'][^>]*?rel=["\'](?:icon|shortcut icon|apple-touch-icon)["\']',
                html, re.I)
            if m and not m.group(1).startswith('data:'):
                return urljoin(base_url, m.group(1))
        except Exception:
            pass
        return None

    def _extract_server_version(self, server):
        """从 Server header 提取版本号，作为兜底"""
        # Apache-Coyote/1.1 (必须在 Apache/... 之前匹配)
        m = re.match(r'Apache-Coyote/([\d.]+)', server, re.I)
        if m: return f'Apache-Coyote {m.group(1)}'
        # Apache/2.4.47 (Win64)
        m = re.match(r'Apache/([\d.]+)', server, re.I)
        if m: return f'Apache {m.group(1)}'
        # nginx/1.18.0, nginx/1.24.0 (Ubuntu)
        m = re.match(r'nginx/([\d.]+)', server, re.I)
        if m: return f'nginx {m.group(1)}'
        # Microsoft-IIS/10.0
        m = re.match(r'Microsoft-IIS/([\d.]+)', server, re.I)
        if m: return f'IIS {m.group(1)}'
        # Virata-EmWeb/R6_2_1 (HP printers)
        m = re.match(r'Virata-EmWeb/([\w\d_.]+)', server, re.I)
        if m: return f'Virata-EmWeb {m.group(1)}'
        # OpenResty/1.21.4
        m = re.match(r'[Oo]pen[Rr]esty/([\d.]+)', server)
        if m: return f'OpenResty {m.group(1)}'
        # lighttpd/1.4.56
        m = re.match(r'lighttpd/([\d.]+)', server, re.I)
        if m: return f'lighttpd {m.group(1)}'
        # gSOAP/2.8
        m = re.match(r'gSOAP/([\d.]+)', server)
        if m: return f'gSOAP {m.group(1)}'
        # PHP/8.0.5
        m = re.search(r'PHP/([\d.]+)', server, re.I)
        if m: return f'PHP {m.group(1)}'
        # squid/frontier-squid-4.13
        m = re.match(r'squid/[^\s]*?(\d+[.\d]+)', server, re.I)
        if m: return f'squid {m.group(1)}'
        # Generic fallback: Product/V[ersion] or Product/version
        m = re.match(r'([^\s/]+)/(?:[Vv])?(\d+[.\d]*)', server)
        if m: return f'{m.group(1)} {m.group(2)}'
        # Multi-word product: "Rapid Logic/1.1", "EPSON UPnP/1.0"
        m = re.match(r'([^\s/]+(?:\s+[^\s/]+)?)/(\d+[.\d]*)', server)
        if m: return f'{m.group(1)} {m.group(2)}'
        return ''

    # ── HTML 解析 ─────────────────────────

    @staticmethod
    def _get_title(html):
        """正则提取标题"""
        if not html:
            return ''
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I | re.S)
        if m: return m.group(1).strip().replace('\r', '').replace('\n', '')
        for tag in ('h1', 'h2', 'h3'):
            m = re.search(rf'<{tag}[^>]*>([^<]+)</{tag}>', html, re.I)
            if m: return m.group(1).strip().replace('\r', '').replace('\n', '')
        m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
        if m: return m.group(1).strip()
        m = re.search(r'<meta[^>]+name=["\']keywords["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
        if m: return m.group(1).strip()
        text = re.sub(r'<[^>]+>', ' ', html).strip()
        return text if len(text) <= 200 else ''

    # ── 输出 ──────────────────────────────

    @staticmethod
    def _save_xlsx(results, output_dir, timestamp):
        filepath = os.path.join(output_dir, f"{timestamp}.xlsx")
        wb = xlsxwriter.Workbook(filepath)
        ws = wb.add_worksheet('Finger scan')
        bold = wb.add_format({"bold": True, "valign": "center"})
        red = wb.add_format({"bold": True, "font_color": "red"})
        yellow = wb.add_format({"bold": True, "font_color": "#FF8C00"})

        headers = ['Url', 'Title', 'CMS', 'Confidence', 'Version',
                   'Server', 'Status', 'Size', 'IP', 'Address', 'ISP', 'DefaultCreds']
        col_widths = [30, 40, 30, 10, 15, 10, 6, 6, 12, 25, 25, 18]
        for i, (h, w) in enumerate(zip(headers, col_widths)):
            ws.set_column(i, i, w)
            ws.write(0, i, h, bold)

        # 加载默认口令库 (大小写不敏感 + 原始key标注)
        default_creds = {}
        creds_orig_keys = {}
        creds_file = os.path.join(path.library, 'default_creds.json')
        if os.path.exists(creds_file):
            with open(creds_file, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            default_creds = {k.lower(): v for k, v in raw.items()}
            creds_orig_keys = {k.lower(): k for k in raw}

        for row, v in enumerate(results, start=1):
            ws.write(row, 0, v.get("url", ""))
            ws.write(row, 1, v.get("title", ""))
            cms = v.get("cms", "-")
            conf = v.get("confidence", 0)
            fmt = red if conf >= 80 else (yellow if conf >= 50 else None)
            ws.write(row, 2, cms, fmt)
            ws.write(row, 3, conf if cms != "-" else "")
            ws.write(row, 4, v.get("version", ""))
            ws.write(row, 5, v.get("Server", ""))
            ws.write(row, 6, v.get("status", ""))
            ws.write(row, 7, v.get("size", ""))
            ws.write(row, 8, v.get("ip", ""))
            ws.write(row, 9, v.get("address", ""))
            ws.write(row, 10, v.get("isp", ""))
            # 默认口令
            creds = []
            if cms and cms != "-":
                seen = set()
                for fp in cms.split(','):
                    fp = fp.strip()
                    fp_lower = fp.lower()
                    # 1. 精确匹配
                    if fp_lower in default_creds:
                        label = creds_orig_keys.get(fp_lower, fp)
                        for c in default_creds[fp_lower]:
                            if '$hostname' in c: continue
                            entry = f"[{label}] {c}"
                            if entry not in seen:
                                creds.append(entry)
                                seen.add(entry)
                    # 2. 模糊匹配: key是产品名子串(来源标注)
                    for k, v in default_creds.items():
                        if k != fp_lower and len(k) >= 4 and k in fp_lower:
                            label = creds_orig_keys.get(k, k)
                            for c in v:
                                if '$hostname' in c: continue
                                entry = f"[{label}] {c}"
                                if entry not in seen:
                                    creds.append(entry)
                                    seen.add(entry)
            ws.write(row, 11, ' | '.join(creds) if creds else "")

        wb.close()
        return filepath
