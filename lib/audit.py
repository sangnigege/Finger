#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""指纹规则质量审计 — 扫描后自动检测可疑规则"""

import os
import json
from collections import Counter, defaultdict


class RuleAudit:
    """分析扫描结果，标记可能存在误报的规则"""

    def __init__(self, finger_path, xlsx_path=None):
        self.finger_path = finger_path
        self.xlsx_path = xlsx_path
        with open(finger_path, 'r', encoding='utf-8') as f:
            self.rules = json.load(f)['fingerprint']

    def run(self, scan_results):
        """scan_results: list[dict], 每个dict含 url/cms/Server/status/title"""
        if not scan_results:
            return []

        # 建立 CMS→规则 索引
        cms_to_rules = defaultdict(list)
        for r in self.rules:
            cms_to_rules[r['cms']].append(r)

        findings = []

        # ── 维度1: 每种指纹的命中统计 ──
        fp_stats = defaultdict(lambda: {
            'total': 0, 'servers': Counter(), 'status_codes': Counter(),
            'titles': Counter(), 'urls': []
        })

        total_fingerprinted = 0
        for row in scan_results:
            cms_str = str(row.get('cms', ''))
            if not cms_str or cms_str in ('None', '-', ''):
                continue
            total_fingerprinted += 1
            server = str(row.get('Server', '')).strip()
            status = str(row.get('status', '')).strip()
            title = str(row.get('title', '')).strip()
            url = str(row.get('url', ''))

            for fp in cms_str.split(','):
                fp = fp.strip()
                if fp:
                    fp_stats[fp]['total'] += 1
                    if server and server != 'None':
                        fp_stats[fp]['servers'][server[:60]] += 1
                    fp_stats[fp]['status_codes'][status] += 1
                    if len(fp_stats[fp]['urls']) < 3:
                        fp_stats[fp]['urls'].append(url)

        # ── 维度2: Server 多样性 ──
        for fp, stats in fp_stats.items():
            unique_servers = len(stats['servers'])
            if unique_servers >= 5:
                top_servers = stats['servers'].most_common(5)
                findings.append({
                    'fingerprint': fp,
                    'hits': stats['total'],
                    'issue': 'Server多样性过高',
                    'detail': f'{unique_servers}种不同Server: {", ".join(s[:40] for s, _ in top_servers)}',
                    'severity': 'HIGH' if unique_servers >= 8 else 'MEDIUM',
                    'suggestion': '该指纹可能匹配了过于通用的特征，建议检查规则关键词',
                    'examples': stats['urls'][:3],
                })

        # ── 维度3: 404 命中率 ──
        for fp, stats in fp_stats.items():
            if stats['total'] >= 5:
                status_404 = stats['status_codes'].get('404', 0)
                ratio_404 = status_404 / stats['total']
                if ratio_404 >= 0.35:
                    findings.append({
                        'fingerprint': fp,
                        'hits': stats['total'],
                        'issue': f'404命中率过高 ({ratio_404:.0%})',
                        'detail': f'{status_404}/{stats["total"]} 次匹配在404页面上',
                        'severity': 'HIGH' if ratio_404 >= 0.5 else 'MEDIUM',
                        'suggestion': '404页面不应匹配产品指纹，建议检查关键词是否过于泛化',
                        'examples': stats['urls'][:3],
                    })

        # ── 维度4: 命中率异常 (单个指纹占比过高) ──
        if total_fingerprinted > 0:
            for fp, stats in fp_stats.items():
                ratio = stats['total'] / total_fingerprinted
                if ratio >= 0.25 and stats['total'] >= 10:
                    findings.append({
                        'fingerprint': fp,
                        'hits': stats['total'],
                        'issue': f'命中率异常 ({ratio:.0%}的已识别URL)',
                        'detail': f'占总识别URL的 {ratio:.1%}，可能存在大面积误报',
                        'severity': 'HIGH' if ratio >= 0.5 else 'MEDIUM',
                        'suggestion': '参考VMware-ESX案例，检查规则是否包含通用HTML标签或泛化关键词',
                        'examples': stats['urls'][:3],
                    })

        # ── 维度5: 规则关键词质量 ──
        # 仅标记真正的通用英文短词，不标记产品专有缩写（如 OKI=打印机, QTS=威联通OS）
        COMMON_WORDS = {
            'the', 'and', 'for', 'not', 'but', 'all', 'can', 'had', 'her',
            'was', 'one', 'our', 'out', 'has', 'are', 'use', 'any', 'see',
            'new', 'get', 'who', 'how', 'its', 'may', 'etc', 'you', 'did',
            'his', 'him', 'she', 'two', 'too', 'run', 'set', 'put', 'add',
            'end', 'let', 'try', 'ask', 'big', 'few', 'lot', 'off', 'old',
            'own', 'pay', 'win', 'yes', 'yet', 'way', 'day', 'man', 'men',
            'now', 'top', 'hot', 'bad', 'boy', 'buy', 'car', 'cat', 'cut',
            'dog', 'dry', 'eat', 'far', 'fit', 'fix', 'fly', 'fun', 'god',
            'hit', 'job', 'key', 'kid', 'law', 'lie', 'low', 'map', 'mix',
            'net', 'oil', 'pop', 'red', 'row', 'sad', 'sit', 'six', 'son',
            'sum', 'sun', 'tax', 'ten', 'tip', 'toy', 'war', 'wet', 'win',
        }
        for r in self.rules:
            for kw in r.get('keyword', []):
                kw_lower = kw.lower()
                # ≤3字符纯英文 且 是常见通用单词（非产品缩写）
                if (len(kw) <= 3 and kw.isascii() and kw.isalpha()
                        and kw_lower in COMMON_WORDS):
                    findings.append({
                        'fingerprint': r['cms'],
                        'hits': fp_stats.get(r['cms'], {}).get('total', 0),
                        'issue': f'高危通用短词: "{kw}"',
                        'detail': f'location={r.get("location")}, logic={r.get("logic","and")}, 该词是常见英文单词，几乎每页都有',
                        'severity': 'HIGH',
                        'suggestion': f'建议删除 "{kw}" 或改为更具体的复合关键词',
                        'examples': [],
                    })
                    break  # 每条规则只报告一次

        # 按严重程度排序
        findings.sort(key=lambda x: (
            0 if x['severity'] == 'HIGH' else 1,
            -x['hits']
        ))

        return findings

    def save_csv(self, findings, output_path):
        """保存审计结果为 CSV"""
        with open(output_path, 'w', encoding='utf-8-sig') as f:
            f.write('Severity,Fingerprint,Hits,Issue,Detail,Suggestion,Examples\n')
            for item in findings:
                examples = ' | '.join(item.get('examples', []))
                f.write(f'{item["severity"]},{item["fingerprint"]},{item["hits"]},'
                        f'"{item["issue"]}","{item["detail"]}","{item["suggestion"]}",'
                        f'"{examples}"\n')

    def print_summary(self, findings):
        """打印审计摘要"""
        high = [f for f in findings if f['severity'] == 'HIGH']
        medium = [f for f in findings if f['severity'] == 'MEDIUM']

        print(f"\n{'='*60}")
        print(f"  规则质量审计报告")
        print(f"{'='*60}")
        print(f"  HIGH: {len(high)} 条  MEDIUM: {len(medium)} 条")
        print()

        if high:
            print("  🔴 HIGH 严重问题:")
            for item in high[:10]:
                print(f"    [{item['fingerprint']}] {item['issue']}")
                print(f"      {item['detail']}")
                print(f"      → {item['suggestion']}")
                if item.get('examples'):
                    print(f"      例: {item['examples'][0]}")
                print()

        if medium:
            print("  🟡 MEDIUM 中等问题:")
            for item in medium[:5]:
                print(f"    [{item['fingerprint']}] {item['issue']}")
                print(f"      {item['detail']}")
                print()
