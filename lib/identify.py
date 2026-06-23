#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author = EASY
import os
import re
import json
from config.data import path
from config.color import color
from urllib.parse import urlsplit
from config.data import logging, Webinfo


class Identify:
    def __init__(self):
        filepath = os.path.join(path.library, 'finger.json')
        with open(filepath, 'r', encoding='utf-8') as file:
            finger = json.load(file)
            for name, value in finger.items():
                self.obj = value
            # 初始化指纹库
            self._prepare_app()

    def run(self, datas):
        self.datas = datas
        matches = self._match_app()
        # 按置信度降序，同名 CMS 只保留最高置信度
        seen = {}
        for m in sorted(matches, key=lambda x: x["confidence"], reverse=True):
            if m["cms"] not in seen:
                seen[m["cms"]] = m
        top = sorted(seen.values(), key=lambda x: x["confidence"], reverse=True)
        cms_list = [m["cms"] for m in top]
        self.datas["cms"] = ','.join(cms_list)
        self.datas["confidence"] = max((m["confidence"] for m in top), default=0)
        self.datas["version"] = ','.join(
            set(m["version"] for m in top if m.get("version"))
        ) or "-"
        _url = "://{0}".format(urlsplit(self.datas['url']).netloc)
        _webinfo = str(Webinfo.result)
        if _url in _webinfo and self.datas["title"] in _webinfo:
            pass
        else:
            results = {
                "url": self.datas["url"],
                "cms": self.datas["cms"],
                "confidence": self.datas["confidence"],
                "version": self.datas["version"],
                "title": self.datas["title"],
                "status": self.datas["status"],
                "Server": self.datas['Server'],
                "size": self.datas["size"],
                "iscdn": self.datas["iscdn"],
                "ip": self.datas["ip"],
                "address": self.datas["address"],
                "isp": self.datas["isp"],
            }
            if cms_list:
                Webinfo.result.insert(0, results)
            else:
                Webinfo.result.append(results)
            Msg = "{0} {1} {2:5} {4} {3}".format(
                color.green(self.datas['cms'] or '-'),
                color.blue(self.datas['Server']),
                self.datas['title'],
                color.yellow(self.datas['status']),
                self.datas["url"],
            )
            logging.success(Msg)

    def match(self, datas):
        """库模式：只做匹配，返回结果 dict，不写全局状态。"""
        self.datas = datas
        matches = self._match_app()
        # 同名 CMS 去重，按置信度取最高
        seen = {}
        for m in sorted(matches, key=lambda x: x["confidence"], reverse=True):
            if m["cms"] not in seen:
                seen[m["cms"]] = m
        top = sorted(seen.values(), key=lambda x: x["confidence"], reverse=True)
        cms_list = [m["cms"] for m in top]
        return {
            "cms": ','.join(cms_list),
            "confidence": max((m["confidence"] for m in top), default=0),
            "version": ','.join(
                set(m["version"] for m in top if m.get("version"))
            ) or "-",
        }

    def _prepare_app(self):
        for line in self.obj:
            if "regula" == line["method"]:
                line["keyword"] = self._prepare_pattern(line["keyword"][0])
            # 预编译版本号正则
            vr = line.get("version_regex", "")
            if vr:
                line["_version_re"] = re.compile(vr, re.I)

    def _prepare_pattern(self, pattern):
        regex, _, rest = pattern.partition('\\;')
        try:
            return re.compile(regex, re.I)
        except re.error:
            return re.compile(r'(?!x)x')

    def _get_match_string(self, location):
        """将 datas 中的值转为匹配用字符串，对 header 做多格式兼容。

        不同指纹库来源的关键词格式不同：
        - Finger 原生: 关键字匹配 dict 的 str() 结果
        - EHole 系列: 关键字用 HTTP 头格式 "Server: nginx"
        - 部分魔改版: 关键字前带 '(' 前缀 "(Server: nginx"
        """
        data = self.datas.get(location, "")
        if location == "header" and hasattr(data, 'items'):
            # 兼容 CaseInsensitiveDict (requests) 和普通 dict
            header_dict = dict(data)
            lines = [str(header_dict)]
            for k, v in header_dict.items():
                lines.append(f"{k}: {v}")
                lines.append(f"{k.lower()}: {v}")
                lines.append(f"({k}: {v}")
            return '\n'.join(lines)
        return str(data)

    def _match_app(self):
        matches = []
        for line in self.obj:
            confidence = line.get('confidence', 100)
            method = line['method']
            matched = False

            if method == "faviconhash":
                if str(self.datas.get("faviconhash", "")) == line["keyword"][0]:
                    matched = True

            elif method == "keyword":
                logic = line.get('logic', 'and')
                loc = line.get("location", "body")
                data_str = self._get_match_string(loc)
                if logic == 'or':
                    matched = any(k in data_str for k in line["keyword"])
                else:  # and (默认，向后兼容)
                    matched = all(k in data_str for k in line["keyword"])

                # 自动降权：body 规则以最短关键词为准评估误报风险
                # OR 逻辑和多关键词等价——任一命中即匹配，最短关键词决定精度
                if matched and loc == "body":
                    kw_list = line.get("keyword", [])
                    kw_count = len(kw_list)
                    min_len = min((len(k) for k in kw_list), default=0)
                    effective_count = 1 if logic == 'or' else kw_count
                    if effective_count == 1:
                        if min_len < 5:
                            confidence = max(confidence - 60, 5)   # e.g. "<a " 每页都有
                        elif min_len < 8:
                            confidence = max(confidence - 40, 10)
                        else:
                            confidence = max(confidence - 20, 20)
                    # AND 多关键词 → 保持原置信度（所有关键词必须同时命中）

            elif method == "regula":
                if line.get("keyword") and hasattr(line["keyword"], 'search'):
                    matched = bool(line["keyword"].search(
                        self.datas.get(line["location"], "")))

            if matched and confidence >= 50:
                version = self._extract_version(line)
                matches.append({
                    "cms": line["cms"],
                    "confidence": confidence,
                    "version": version,
                })

        return matches

    def _extract_version(self, rule):
        """从响应中提取版本号"""
        version_re = rule.get("_version_re")
        if not version_re:
            return None
        loc = rule.get("version_location", rule.get("location", "body"))
        data_str = str(self.datas.get(loc, ""))
        m = version_re.search(data_str)
        return m.group(1) if m else None
