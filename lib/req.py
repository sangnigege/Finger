#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author = EASY
import requests
import random
import re
import base64
import mmh3
from lib.ip_factory import IPFactory
from urllib.parse import urlsplit, urljoin
from config.data import Urls, Webinfo, Urlerror, logging, Extra
from config import settings
from lib.identify import Identify
import urllib3

urllib3.disable_warnings()
from concurrent.futures import ThreadPoolExecutor


class Request:
    def __init__(self):
        Webinfo.result = []
        Urlerror.result = []
        self.checkcms = Identify()
        self.ipFactory = IPFactory()
        with ThreadPoolExecutor(settings.threads) as pool:
            run = pool.map(self.apply, set(Urls.url))

    def apply(self, url):
        try:
            #proxies = { "http": "127.0.0.1:8080","https": "127.0.0.1:8080"}
            with requests.get(url, timeout=10, headers=self.get_headers(), verify=False,
                              allow_redirects=True, stream=True, proxies=settings.get_proxies()) as response:
                if int(response.headers.get("content-length", default=1000)) > 100000:
                    self.response(url, response, True)
                else:
                    self.response(url, response)
        except KeyboardInterrupt:
            logging.error("用户强制程序，系统中止!")
            exit(0)
        except Exception as e:
            results = {"url": str(url), "cms": "-", "title": str(e),
                       "status": "-", "Server": "-",
                       "size": "-", "iscdn": "-", "ip": "-",
                       "address": "-", "isp": "-"}

            Urlerror.result.append(results)
            pass

    def response(self, url, response, ignore=False):
        if ignore:
            html = ""
            size = response.headers.get("content-length", default=1000)
        else:
            response.encoding = response.apparent_encoding if response.encoding == 'ISO-8859-1' else response.encoding
            response.encoding = "utf-8" if response.encoding is None else response.encoding
            html = response.content.decode(response.encoding,"ignore")
            size = len(response.text)

        title = self.get_title(html).strip().replace('\r', '').replace('\n', '')
        status = response.status_code
        server = response.headers["Server"] if "Server" in response.headers else ""
        server = "" if len(server) > 50 else server

        # 正则提取 favicon 路径，回退到 /favicon.ico
        favicon_url_hint = None
        if html:
            parsed = urlsplit(url)
            base = parsed.scheme + "://" + parsed.netloc
            favicon_url_hint = self._find_favicon_href(html, base)

        faviconhash = self.get_faviconhash(url, favicon_url_hint)
        # CDN 检测：默认关闭，--cdn 开启
        if Extra.cdn:
            iscdn, iplist = self.ipFactory.factory(url)
            if iscdn == 0 and self.ipFactory.check_cdn_headers(response.headers):
                iscdn = 1
            iplist = ','.join(set(iplist))
        else:
            iscdn, iplist = 0, ""
        datas = {"url": url, "title": title, "body": html, "status": status, "Server": server, "size": size,
                 "header": response.headers, "faviconhash": faviconhash, "iscdn": iscdn, "ip": iplist,
                 "address": "", "isp": ""}
        self.checkcms.run(datas)

    def get_faviconhash(self, url, favicon_url_hint=None):
        favicon_url = url
        try:
            parsed = urlsplit(url)
            base = parsed.scheme + "://" + parsed.netloc
            favicon_url = favicon_url_hint if favicon_url_hint else urljoin(base, "favicon.ico")
            favicon_headers = self.get_headers()
            favicon_headers['Accept'] = 'image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5'
            favicon_headers['Sec-Fetch-Dest'] = 'image'
            favicon_headers['Sec-Fetch-Mode'] = 'no-cors'
            favicon_headers['Sec-Fetch-Site'] = 'same-origin'
            favicon_headers.pop('Upgrade-Insecure-Requests', None)
            favicon_headers.pop('Sec-Fetch-User', None)
            response = requests.get(favicon_url, headers=favicon_headers, timeout=4, proxies=settings.get_proxies())
            favicon_raw = response.content
            # 兼容 Finger/EHole 现有规则（MIME base64）
            hash_ehole = mmh3.hash(base64.encodebytes(favicon_raw))
            # 同时也返回 fofa 兼容 hash 用于匹配
            return {'ehole': hash_ehole, 'fofa': mmh3.hash(base64.b64encode(favicon_raw))}
        except Exception as e:
            logging.warning("favicon 获取失败: {0} → {1}".format(favicon_url, str(e)))
            return {'ehole': 0, 'fofa': 0}

    def _find_favicon_href(self, html, base_url):
        """正则提取 favicon 路径"""
        try:
            m = re.search(
                r'<link[^>]+rel=["\'](?:icon|shortcut icon|apple-touch-icon)["\'][^>]+href=["\']([^"\']+)["\']',
                html, re.I)
            if m and not m.group(1).startswith('data:'):
                return urljoin(base_url, m.group(1))
        except Exception:
            pass
        return None

    @staticmethod
    def get_title(html):
        if not html:
            return ''
        # <title>...</title>
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I | re.S)
        if m: return m.group(1).strip()
        # <h1>
        for tag in ('h1', 'h2', 'h3'):
            m = re.search(rf'<{tag}[^>]*>([^<]+)</{tag}>', html, re.I)
            if m: return m.group(1).strip()
        # <meta name="description" content="...">
        m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
        if m: return m.group(1).strip()
        # <meta name="keywords" content="...">
        m = re.search(r'<meta[^>]+name=["\']keywords["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
        if m: return m.group(1).strip()
        # 纯文本兜底
        text = re.sub(r'<[^>]+>', ' ', html).strip()
        return text if len(text) <= 200 else ''

    def get_headers(self):
        """
        生成伪造请求头
        """
        ua = random.choice(settings.user_agents)
        headers = {
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
        return headers

