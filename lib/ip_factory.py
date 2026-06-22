#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author = EASY
import os
import re
import json
import socket
import ipaddress
from urllib.parse import urlsplit
from config.data import path

# CDN 响应头特征，只有 CDN 才会设置这些头，误报率极低
CDN_HEADER_KEYS = {
    'cf-ray',              # Cloudflare
    'cf-cache-status',     # Cloudflare
    'cf-connecting-ip',    # Cloudflare
    'x-amz-cf-id',         # AWS CloudFront
    'x-amz-cf-pop',        # AWS CloudFront
    'x-served-by',         # Fastly
    'x-timer',             # Fastly
    'x-cache-hits',        # Fastly
    'x-akamai-transformed',# Akamai
    'x-akamai-request-id', # Akamai
    'x-edge-ip',           # EdgeCast / StackPath
    'x-cdn-forwarded',     # CDN77
    'x-cacheable',         # StackPath
    'x-edge-location',     # AWS CloudFront
    'x-hw',                # Huawei CDN
    'x-ccn',               # ChinaCache
    'x-ws-request-id',     # Wangsu CDN
}


class IPFactory:
    def __init__(self):
        cdnFile = os.path.join(path.library, 'cdn_ip_cidr.json')
        with open(cdnFile, 'r', encoding='utf-8') as file:
            self.cdns = json.load(file)

    def parse_host(self, url):
        host = urlsplit(url).netloc
        if ':' in host:
            host = re.sub(r':\d+', '', host)
        return host

    def factory(self, url):
        """根据 DNS 解析和 CDN CIDR 列表判断是否为 CDN"""
        ip_list = []
        try:
            host = self.parse_host(url)
            items = socket.getaddrinfo(host, 0)
            for ip in items:
                if ip[4][0] not in ip_list:
                    ip_list.append(ip[4][0])
            if len(ip_list) > 1:
                return 1, ip_list
            elif ip_list:
                for cdn in self.cdns:
                    if ipaddress.ip_address(ip_list[0]) in ipaddress.ip_network(cdn):
                        return 1, ip_list
            return 0, ip_list
        except Exception:
            return 0, ip_list

    @staticmethod
    def check_cdn_headers(headers):
        """根据响应头判断是否为 CDN（补充 CIDR 检测的盲区）"""
        if not headers:
            return False
        header_keys = {k.lower() for k in headers.keys()}
        return bool(header_keys & CDN_HEADER_KEYS)
