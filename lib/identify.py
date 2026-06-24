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
            # 预编译设备型号正则
            mr = line.get("model_regex", "")
            if mr:
                line["_model_re"] = re.compile(mr, re.I)

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
        - url 匹配: 同时生成完整 URL / 路径+查询 / 纯路径三行，覆盖各种路径关键词
        """
        data = self.datas.get(location, "")
        if location == "url":
            url = str(data)
            parsed = urlsplit(url)
            path_qs = parsed.path + ('?' + parsed.query if parsed.query else '')
            # 兼容带/不带尾部斜杠: /actuator 和 /actuator/ 互相匹配
            path = parsed.path.rstrip('/')
            return '\n'.join([url, path_qs, parsed.path, path, path + '/'])
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
            method = line['method']
            matched = False
            matched_keywords = []

            # ── faviconhash: 密码学哈希 → 直接 95 分，不走算法 ──
            if method == "faviconhash":
                fav = self.datas.get("faviconhash", {})
                target = line["keyword"][0]
                if isinstance(fav, dict):
                    matched = (str(fav.get('ehole', '')) == target or
                               str(fav.get('fofa', '')) == target or
                               str(fav.get('md5', '')) == target)
                else:
                    matched = str(fav) == target

                if matched:
                    ver_num = self._extract_version(line)
                    version = f"{line['cms']} {ver_num}" if ver_num else None
                    model = self._extract_model(line)
                    if model:
                        version = (version + ' ' if version else '') + f"[{model}]"
                    matches.append({
                        "cms": line["cms"],
                        "confidence": 95,
                        "version": version,
                    })
                    continue

            # ── keyword: 统计命中关键词 → 算法计算置信度 ──
            elif method == "keyword":
                logic = line.get('logic', 'and')
                loc = line.get("location", "body")
                data_str = self._get_match_string(loc)

                if logic == 'or':
                    # 统计所有命中的关键词（不再用 any() 提前退出）
                    matched_keywords = [k for k in line["keyword"] if k in data_str]
                    matched = bool(matched_keywords)
                else:  # and
                    matched = all(k in data_str for k in line["keyword"])
                    if matched:
                        matched_keywords = list(line["keyword"])

            # ── regula: 正则匹配 → 算法计算置信度 ──
            elif method == "regula":
                if line.get("keyword") and hasattr(line["keyword"], 'search'):
                    matched = bool(line["keyword"].search(
                        self.datas.get(line["location"], "")))

            # ── 统一计算置信度 ──
            if matched:
                confidence = self._compute_confidence(line, matched_keywords)
                ver_num = self._extract_version(line)
                version = f"{line['cms']} {ver_num}" if ver_num else None
                model = self._extract_model(line)
                if model:
                    version = (version + ' ' if version else '') + f"[{model}]"
                matches.append({
                    "cms": line["cms"],
                    "confidence": confidence,
                    "version": version,
                })

        return matches

    def _compute_confidence(self, rule, matched_keywords):
        """完全自动化的置信度计算——不依赖规则中预设的 confidence 字段。

        原则: 置信度从匹配过程本身推导，不从事先标注。
         - faviconhash 已在 _match_app 中直接返回 95，不进入此方法
         - keyword 匹配根据 位置/逻辑/命中率/关键词质量 计算
         - regula 匹配取保守值
        """
        method = rule.get('method', 'keyword')
        loc = rule.get('location', 'body')
        logic = rule.get('logic', 'and')
        total_kw = len(rule.get('keyword', []))
        hit_count = len(matched_keywords)

        # ── Step 1: 方法基础分 ──
        if method == 'regula':
            base = 50   # 正则: 特异性取决于正则质量，取保守值
        else:
            base = 55   # keyword: 基线

        # ── Step 2: 位置调整 (title/url 最可靠, header 次之, body 最弱) ──
        if loc == 'title':
            base += 25
        elif loc == 'url':
            base += 25   # URL 路径匹配与 title 同等可靠
        elif loc == 'header':
            base += 10

        # ── Step 3: 逻辑 + 命中率 (AND全命中 > OR高命中率 > OR低命中率) ──
        if logic == 'and':
            if total_kw >= 2:
                base += 15   # 多关键词 AND: 全部命中 → 误报概率极低
            else:
                base += 5    # 单关键词 AND: 等同单点匹配
        else:  # OR
            if total_kw >= 2:
                ratio = hit_count / total_kw
                base += int(ratio * 15)  # 命中1/10≈+1, 5/10≈+7, 10/10=+15
            # 单关键词 OR: 最不可靠, +0

        # ── Step 4: 关键词风险惩罚 ──
        for kw in matched_keywords:
            # ≤3 字符纯英文 → 如 "php" "asp" "body" → 几乎每页都有
            if len(kw) <= 3 and kw.isascii() and kw.isalpha():
                base -= 20
            # 短 HTML 标签 → "<span>" "<div>" 等
            elif kw.startswith('<') and len(kw) < 15:
                base -= 15
            # 短 URL 路径在 body 中 → 是链接而非页面本身 (url location 不惩罚)
            elif kw.startswith('/') and loc == 'body' and len(kw) < 30:
                base -= 10

        # ── Step 5: Server header 交叉校验（仅对配置了 expected_server 的规则生效） ──
        expected = rule.get('expected_server', [])
        if expected:
            server = str(self.datas.get('Server', '')).lower()
            if not any(e.lower() in server for e in expected):
                base -= 20  # Server 不匹配 → 大概率 FP

        return max(10, min(100, base))

    def _extract_version(self, rule):
        """从响应中提取版本号"""
        version_re = rule.get("_version_re")
        if not version_re:
            return None
        loc = rule.get("version_location", rule.get("location", "body"))
        data_str = str(self.datas.get(loc, ""))
        m = version_re.search(data_str)
        return m.group(1) if m else None

    def _extract_model(self, rule):
        """从响应中提取设备型号（硬件指纹）"""
        model_re = rule.get("_model_re")
        if not model_re:
            return None
        loc = rule.get("model_location", rule.get("location", "body"))
        data_str = str(self.datas.get(loc, ""))
        m = model_re.search(data_str)
        return m.group(0) if m else None
