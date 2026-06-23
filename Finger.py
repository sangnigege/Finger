#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author = EASY
import os
import warnings
from config import settings
from config.data import Extra, Webinfo, Urls, path, logging
from lib.cmdline import cmdline
from lib.checkenv import CheckEnv
from lib.finger import Finger
from lib.output import Output
from lib.ip_attributable import IpAttributable
from colorama import init as wininit
from lib.options import initoptions

# 过滤第三方库在新版 Python 下的 DeprecationWarning
warnings.filterwarnings("ignore", category=DeprecationWarning, module="xlsxwriter")

wininit(autoreset=True)

if __name__ == '__main__':
    # 打印logo
    print(settings.Banner)
    # 检测环境
    check = CheckEnv()
    # 加载参数
    options = initoptions(cmdline())
    # 扫描 (使用统一的 Finger 引擎)
    f = Finger(threads=settings.threads)
    Webinfo.result = f.scan(list(set(Urls.url)), timeout=settings.timeout)
    # IP归属地
    if Extra.geo:
        IpAttributable()
    # 输出
    save = Output()
    # 审计
    if Extra.audit:
        from lib.audit import RuleAudit
        audit = RuleAudit(
            finger_path=os.path.join(path.library, 'finger.json'),
        )
        findings = audit.run(Webinfo.result)
        audit.print_summary(findings)
        if findings:
            latest = getattr(save, 'path_xls', os.path.join(path.output, 'audit.csv'))
            csv_path = latest.replace('.xlsx', '_audit.csv')
            audit.save_csv(findings, csv_path)
            logging.success(f"审计报告已保存: {csv_path}")



