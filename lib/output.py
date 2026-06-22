#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author = EASY
import os
import time
import json
import base64
import xlsxwriter
from config.data import path,Webinfo,Save,Urlerror
from config.data import logging

class Output:
    def __init__(self):
        self.nowTime = time.strftime("%Y%m%d%H%M%S",time.localtime())
        Webinfo.result = Webinfo.result + Urlerror.result
        self.filename_json = self.nowTime + '.json'
        self.filename_xls = self.nowTime + '.xlsx'
        self.path_json = os.path.join(path.output,self.filename_json)
        self.path_xls = os.path.join(path.output,self.filename_xls)
        if Save.format == 'json' and Webinfo.result:
            self.outJson()
        if Save.format == 'xlsx' and Webinfo.result:
            self.outXls()


    def outJson(self):
        with open(self.path_json,'w') as file:
            file.write(json.dumps(Webinfo.result))
        print()
        successMsg = "结果文件输出路径为:{0}".format(self.path_json)
        logging.success(successMsg)

    def outXls(self):
        with xlsxwriter.Workbook(self.path_xls) as workbook:
            worksheet = workbook.add_worksheet('Finger scan')
            bold = workbook.add_format({"bold":True,"valign":"center"})
            red = workbook.add_format({"bold": True, "font_color": "red", "valign": "center"})
            yellow = workbook.add_format({"bold": True, "font_color": "#FF8C00", "valign": "center"})

            worksheet.set_column('A:A', 30)
            worksheet.set_column('B:B', 40)
            worksheet.set_column('C:C', 25)
            worksheet.set_column('D:D', 10)
            worksheet.set_column('E:E', 10)
            worksheet.set_column('F:F', 10)
            worksheet.set_column('G:G', 15)
            worksheet.set_column('H:H', 15)
            worksheet.set_column('I:I', 10)
            worksheet.set_column('J:J', 30)
            worksheet.set_column('K:K', 30)

            # 表头 — 新增 confidence, version
            headers = [
                ('A1', 'Url'),
                ('B1', 'Title'),
                ('C1', 'CMS'),
                ('D1', 'Confidence'),
                ('E1', 'Version'),
                ('F1', 'Server'),
                ('G1', 'Status'),
                ('H1', 'Size'),
                ('I1', 'IP'),
                ('J1', 'Address'),
                ('K1', 'ISP'),
            ]
            for cell, text in headers:
                worksheet.write(cell, text, bold)

            for row, value in enumerate(Webinfo.result, start=1):
                worksheet.write(row, 0, value.get("url", ""))
                worksheet.write(row, 1, value.get("title", ""))
                # CMS 列根据置信度着色
                cms = value.get("cms", "-")
                confidence = value.get("confidence", 0)
                if confidence >= 90:
                    worksheet.write(row, 2, cms, red)
                elif confidence >= 50:
                    worksheet.write(row, 2, cms, yellow)
                else:
                    worksheet.write(row, 2, cms)
                worksheet.write(row, 3, confidence if cms != "-" else "")
                worksheet.write(row, 4, value.get("version", ""))
                worksheet.write(row, 5, value.get("Server", ""))
                worksheet.write(row, 6, value.get("status", ""))
                worksheet.write(row, 7, value.get("size", ""))
                worksheet.write(row, 8, value.get("ip", ""))
                worksheet.write(row, 9, value.get("address", ""))
                worksheet.write(row, 10, value.get("isp", ""))

        print()
        successMsg = "结果文件输出路径为:{0}".format(self.path_xls)
        logging.success(successMsg)
