#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author = EASY
import os
from config.data import path
from config.data import Webinfo
from lib.ip2region import Searcher
from lib.ip2region.util import IPv4


class IpAttributable:
    def __init__(self):
        dbFile = os.path.join(path.library, "data", "ip2region.xdb")
        self.searcher = Searcher(IPv4, dbFile, None, None)
        self.getAttributable()
        self.searcher.close()


    def ipCollection(self):
        ip_list = []
        for value in Webinfo.result:
            if value["iscdn"] == 0 and value["ip"] not in ip_list:
                ip_list.append(value["ip"])
        return ip_list

    def getAttributable(self):
        ips = self.ipCollection()
        try:
            for ip in ips:
                addr = []
                result = self.searcher.search(ip)
                if not result:
                    continue
                # v3 格式: 国家|省份|城市|ISP|国家代码
                data = result.split("|")
                isp = data[3].replace("0", "") if len(data) > 3 else ""
                for i, ad in enumerate(data):
                    if i == 4:  # 跳过国家代码
                        continue
                    if ad != "0" and ad not in addr and ad != "":
                        addr.append(ad)
                address = ','.join(addr)
                for value in Webinfo.result:
                    if value['ip'] == ip:
                        Webinfo.result[Webinfo.result.index(value)]["address"] = address
                        Webinfo.result[Webinfo.result.index(value)]["isp"] = isp
        except Exception as e:
            pass

