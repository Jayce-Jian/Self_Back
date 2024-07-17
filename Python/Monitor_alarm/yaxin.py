# -*- coding:utf-8 -*-

import re
import bs4
import requests
from config import CONFIG
from time_function import time_format
# 关闭requests的ssl证书提醒
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


YaXin_Cookie = CONFIG['yaxin']['Cookie']
Time_Interval = CONFIG['time_interval']['Interval']  # 查询时间跨度
start_time, end_time = time_format(Time_Interval)

if Time_Interval == "day":
    Time_Range = "1"
else:
    Time_Range = "0"

From_Day = start_time[0:10]
To_Day = From_Day
From_Time = start_time[-5:]
To_Time = end_time[-5:]


def yaxin():
    YaXin_HEADERS = {
        'Host': 'host.cn',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '2222',
        'Origin': 'host.cn',
        'Connection': 'keep-alive',
        'Referer': 'https://host.cn/hsot--AntiMalwareEvents.screen',
        'Cookie': YaXin_Cookie,
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'iframe',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1'
    }
    
    YaXin_PostData = {
        "rID": "xxxxxxxxxxxx",
        "cmdArguments": "",
        "embedded": "false",
        "command": "RESETPAGING",
        "changed": "false",
        "searchOpen": "",
        "scrollTop": "",
        "scrollLeft": "",
        "tagFilter_type": "0",
        "tagFilter_tags": "",
        "tagFilter_goToID": "",
        "qHidden": "",
        "q": "",
        "timeRange": Time_Range,
        "timeRange2": "",
        "fromDate": From_Day,
        "fromTime": From_Time,
        "toDate": To_Day,
        "toTime": To_Time,
        "hostFilter": "0",
        "hostFilter2": "",
        "hostFilterHostGroupID": "",
        "hostFilterHostGroupID_tree_viewstate": "root",
        "hostFilterHostGroupID_tree_selected": "root",
        "hostFilterHostGroupID2": "",
        "hostFilterSecurityProfileID": "",
        "hostFilterSecurityProfileID_tree_viewstate": "tvi_1",
        "hostFilterSecurityProfileID_tree_selected": "0",
        "hostFilterSecurityProfileID2": "",
        "hostFilterHostID2": "",
        "searchActive_0": "true",
        "searchColumn_0": "summaryHostname",
        "searchType_0": "LIKE",
        "searchQuery_0": "",
        "searchActive_1": "false",
        "searchColumn_1": "summaryHostname",
        "searchType_1": "LIKE",
        "searchQuery_1": "",
        "searchActive_2": "false",
        "searchColumn_2": "summaryHostname",
        "searchType_2": "LIKE",
        "searchQuery_2": "",
        "searchActive_3": "false",
        "searchColumn_3": "summaryHostname",
        "searchType_3": "LIKE",
        "searchQuery_3": "",
        "searchActive_4": "false",
        "searchColumn_4": "summaryHostname",
        "searchType_4": "LIKE",
        "searchQuery_4": "",
        "mainTable_selected": "57744",
        "mainTable_selectedItems": "57744",
        "mainTable_selectedGroup": "",
        "mainTable_selectedGroups": "",
        "mainTable_selectedGroupIdentifiers": "",
        "mainTable_sortIndex": "3",
        "mainTable_sortColumnName": "summaryInfectedFilePath",
        "mainTable_sortAsc": "true",
        "mainTable_viewstate": "|summaryInfectedFilePath,width=921|summaryMalware,width=303|summaryScanResult,width=214|summaryTagsHTML,width=107",
        "mainTable_groupByIndex": "-1"
    }

    yaxin = 'https://host.cn/host--AntiMalwareEvents.screen'

    yaxin_req = requests.post(yaxin, headers=YaXin_HEADERS, data=YaXin_PostData, verify=False)
    
    content = bs4.BeautifulSoup(yaxin_req.content.decode("utf-8"), "lxml")
    result_element = content.find_all(id='mainTable_rows_table')

    alarm_element = result_element[0].find_all('tr',class_="datatable_row")
    result_str = ""
    
    for i in alarm_element:
        alarm_table = i.find_all('div',class_="datatable_text")

        dr = re.compile(r'<[^>]+>',re.S)
        alarm_info = dr.sub('',str(alarm_table))
        alarm_info = alarm_info.strip('[').strip(']').split(",")

        tmp_time = alarm_info[0]
        tmp_ip = alarm_info[1][1:]
        # 确定的攻击IP不用查
        # 已隔离，不用再查
        if tmp_ip in ['xxx.xxx.xxx.xxx']:
            continue
        tmp_content = alarm_info[2][1:]
        if tmp_content != "多个":
            tmp_content = tmp_content[0:30]
        tmp_type = alarm_info[3][1:]
        tmp_todo = alarm_info[4][1:]
        if tmp_todo == "已隔离":
            continue
        
        result_str += "时间：{} | IP：{} | 感染的文件：{} | 类型：{}\n".format(tmp_time, tmp_ip, tmp_content, tmp_type)
    if  result_str:
        print("\n↙↙↙亚信服务器安全防护未处理告警：↘↘↘")
        print(result_str)
    else:
        print("\n --> 亚信无异常告警！\n")