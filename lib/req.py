#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author = EASY
import requests
import random
import base64
import mmh3
from lib.ip_factory import IPFactory
from urllib.parse import urlsplit, urljoin
from config.data import Urls, Webinfo, Urlerror, logging
from config import settings
from lib.identify import Identify
from bs4 import BeautifulSoup
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
                              allow_redirects=True, stream=True) as response:
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

        # 只解析一次 HTML，共用给标题提取和 favicon 路径发现
        soup = BeautifulSoup(html, 'html.parser') if html else None

        title = self.get_title(soup, html).strip().replace('\r', '').replace('\n', '')
        status = response.status_code
        server = response.headers["Server"] if "Server" in response.headers else ""
        server = "" if len(server) > 50 else server

        # 从 html soup 中提取 favicon 路径，回退到 /favicon.ico
        favicon_url_hint = None
        if soup:
            parsed = urlsplit(url)
            base = parsed.scheme + "://" + parsed.netloc
            favicon_url_hint = self._find_favicon_in_soup(soup, base)

        faviconhash = self.get_faviconhash(url, favicon_url_hint)
        iscdn, iplist = self.ipFactory.factory(url)
        # CIDR 未检测到 CDN 时，用响应头二次确认
        if iscdn == 0 and self.ipFactory.check_cdn_headers(response.headers):
            iscdn = 1
        iplist = ','.join(set(iplist))
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
            response = requests.get(favicon_url, headers=favicon_headers, timeout=4)
            favicon_raw = response.content
            # 兼容 Finger/EHole 现有规则（MIME base64）
            hash_ehole = mmh3.hash(base64.encodebytes(favicon_raw))
            # 同时也返回 fofa 兼容 hash 用于匹配
            return {'ehole': hash_ehole, 'fofa': mmh3.hash(base64.b64encode(favicon_raw))}
        except Exception as e:
            logging.warning("favicon 获取失败: {0} → {1}".format(favicon_url, str(e)))
            return {'ehole': 0, 'fofa': 0}

    def _find_favicon_in_soup(self, soup, base_url):
        """从已解析的 HTML soup 中提取 favicon 路径"""
        try:
            for link in soup.find_all('link', rel=['icon', 'shortcut icon', 'apple-touch-icon']):
                href = link.get('href')
                if href and not href.startswith('data:'):
                    return urljoin(base_url, href)
        except Exception:
            pass
        return None

    def get_title(self, soup, html):
        if soup is None:
            return ''
        title = soup.title
        if title and title.text:
            return title.text
        if soup.h1:
            return soup.h1.text
        if soup.h2:
            return soup.h2.text
        if soup.h3:
            return soup.h3.text
        desc = soup.find('meta', attrs={'name': 'description'})
        if desc:
            return desc['content']

        word = soup.find('meta', attrs={'name': 'keywords'})
        if word:
            return word['content']

        text = soup.text
        if len(text) <= 200:
            return text
        return ''

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

