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
import requests
import mmh3
import urllib3
from urllib.parse import urlsplit, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from bs4 import BeautifulSoup
from config.data import path, logging
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

    def scan(self, urls, timeout=10):
        """扫描 URL 列表，返回识别结果列表。

        Args:
            urls: URL 字符串列表
            timeout: HTTP 请求超时（秒）

        Returns:
            list[dict]: 每个 URL 一个结果，包含:
                url, cms, confidence, version, title,
                status, Server, size, faviconhash,
                iscdn, ip, address, isp
        """
        results = []
        errors = []
        unique_urls = list(set(urls))

        with ThreadPoolExecutor(self.threads) as pool:
            futures = {
                pool.submit(self._scan_one, url, timeout): url
                for url in unique_urls
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except KeyboardInterrupt:
                    logging.error("用户强制中止!")
                    break
                except Exception as e:
                    errors.append({
                        "url": url,
                        "cms": "-",
                        "title": str(e),
                        "status": "-",
                        "Server": "-",
                        "size": "-",
                        "iscdn": "-",
                        "ip": "-",
                        "address": "-",
                        "isp": "-",
                        "confidence": 0,
                        "version": "-",
                    })

        # 有 CMS 的结果优先排在前面
        results.sort(key=lambda r: (r.get("confidence", 0), r.get("cms") != ""),
                     reverse=True)
        return results + errors

    def scan_and_save(self, urls, output_dir=None, fmt="xlsx", timeout=10):
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
            import json as _json
            filepath = os.path.join(output_dir, f"{ts}.json")
            with open(filepath, 'w') as f:
                _json.dump(results, f, ensure_ascii=False, indent=2)
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
            size = len(response.text)

        soup = BeautifulSoup(html, 'html.parser') if html else None
        title = self._get_title(soup)
        server = response.headers.get("Server", "")
        server = "" if len(server) > 50 else server

        # favicon
        favicon_url_hint = None
        if soup:
            parsed = urlsplit(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            favicon_url_hint = self._find_favicon(soup, base)
        faviconhash = self._get_faviconhash(url, favicon_url_hint)

        # CDN/IP
        try:
            iscdn, iplist = self.ip_factory.factory(url)
            if iscdn == 0 and self.ip_factory.check_cdn_headers(response.headers):
                iscdn = 1
            iplist_str = ','.join(set(iplist))
        except Exception:
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

        return {
            "url": url,
            "cms": match_info["cms"],
            "confidence": match_info["confidence"],
            "version": match_info["version"],
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
            resp = requests.get(target, headers=h, timeout=4)
            raw = resp.content
            return {'ehole': mmh3.hash(base64.encodebytes(raw)),
                    'fofa': mmh3.hash(base64.b64encode(raw))}
        except Exception as e:
            logging.warning(f"favicon 获取失败: {favicon_url} → {e}")
            return {'ehole': 0, 'fofa': 0}

    def _find_favicon(self, soup, base_url):
        try:
            for link in soup.find_all('link', rel=['icon', 'shortcut icon', 'apple-touch-icon']):
                href = link.get('href')
                if href and not href.startswith('data:'):
                    return urljoin(base_url, href)
        except Exception:
            pass
        return None

    # ── HTML 解析 ─────────────────────────

    @staticmethod
    def _get_title(soup):
        if soup is None:
            return ''
        title = soup.title
        if title and title.text:
            return title.text.strip().replace('\r', '').replace('\n', '')
        for tag in ('h1', 'h2', 'h3'):
            el = getattr(soup, tag)
            if el and el.text:
                return el.text.strip().replace('\r', '').replace('\n', '')
        desc = soup.find('meta', attrs={'name': 'description'})
        if desc and desc.get('content'):
            return desc['content']
        kw = soup.find('meta', attrs={'name': 'keywords'})
        if kw and kw.get('content'):
            return kw['content']
        text = soup.text
        return text if len(text) <= 200 else ''

    # ── 输出 ──────────────────────────────

    @staticmethod
    def _save_xlsx(results, output_dir, timestamp):
        import xlsxwriter
        filepath = os.path.join(output_dir, f"{timestamp}.xlsx")
        wb = xlsxwriter.Workbook(filepath)
        ws = wb.add_worksheet('Finger scan')
        bold = wb.add_format({"bold": True, "valign": "center"})
        red = wb.add_format({"bold": True, "font_color": "red"})
        yellow = wb.add_format({"bold": True, "font_color": "#FF8C00"})

        headers = ['Url', 'Title', 'CMS', 'Confidence', 'Version',
                   'Server', 'Status', 'Size', 'IP', 'Address', 'ISP']
        for i, h in enumerate(headers):
            ws.set_column(i, i, max(len(h) + 5, 12))
            ws.write(0, i, h, bold)

        for row, v in enumerate(results, start=1):
            ws.write(row, 0, v.get("url", ""))
            ws.write(row, 1, v.get("title", ""))
            cms, conf = v.get("cms", "-"), v.get("confidence", 0)
            fmt = red if conf >= 90 else (yellow if conf >= 50 else None)
            ws.write(row, 2, cms, fmt)
            ws.write(row, 3, conf if cms else "")
            ws.write(row, 4, v.get("version", ""))
            ws.write(row, 5, v.get("Server", ""))
            ws.write(row, 6, v.get("status", ""))
            ws.write(row, 7, v.get("size", ""))
            ws.write(row, 8, v.get("ip", ""))
            ws.write(row, 9, v.get("address", ""))
            ws.write(row, 10, v.get("isp", ""))

        wb.close()
        return filepath
