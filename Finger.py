#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author = EASY
import warnings
from config import settings
from config.data import Extra
from lib.cmdline import cmdline
from lib.checkenv import CheckEnv
from lib.req import Request
from lib.output import Output
from lib.ip_attributable import IpAttributable
from colorama import init as wininit
from lib.options import initoptions

# 过滤第三方库在新版 Python 下的 DeprecationWarning
warnings.filterwarnings("ignore", category=DeprecationWarning, module="bs4")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="xlsxwriter")

wininit(autoreset=True)

if __name__ == '__main__':
    # 打印logo
    print(settings.Banner)
    # 检测环境
    check = CheckEnv()
    # 加载参数
    options = initoptions(cmdline())
    run = Request()
    if Extra.geo:
        IpAttributable()
    save = Output()








