# -*- coding:utf-8 -*-
######################################
#        奇安信网神分析平台          #
#             阿里云盾               #
#   亚信安全服务器深度安全防护系统   #
######################################
import json
import time
import requests
from config import CONFIG
from time_function import time_timestamp
from yaxin import yaxin
# 关闭requests的ssl证书提醒
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


YunDun_Cookie = CONFIG['yundun']['Cookie']  # 云盾Cookie
TianYan_Cookie = CONFIG['tianyan']['Cookie']  # 天眼Cookie
Query_Interval = CONFIG['query_interval']['Interval']  # 查询间隔
Time_Interval = CONFIG['time_interval']['Interval']  # 查询时间跨度


def format_tstamp(tstamp):
    tstamp = tstamp / 1000
    time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tstamp))
    return time_string


def yundun():
    YunDun_HEADERS = {
        'Host': 'host.cn',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'refer.host.cn/',
        'Connection': 'keep-alive',
        'Cookie': YunDun_Cookie,
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }

    # 待处理紧急告警
    yundun = 'https://host.cn/DescribeAlarmEventList.json?regionId=xxxxxxxxxx&data={"From":"xxx","Levels":"serious","Dealed":"N","PageSize":20,"CurrentPage":1}'

    yundun_req = requests.get(yundun, headers=YunDun_HEADERS, verify=False)
    json_yundun = json.loads(yundun_req.text)
    
    return json_yundun


def tianyan():
    TianYan_HEADERS = {
        'Host': 'host.cn',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Referer': 'https://host.cn/skyeye/home/alarm/alarm',
        'Cookie': TianYan_Cookie,
        'TE': 'Trailers'
    }
    # 只查当日 "攻击成功" 和 "失陷" 的告警
    start_time, end_time = time_timestamp(Time_Interval)
    tianyan_url = 'https://host.cn/skyeye/v1/alarm/alarm/list?offset=1&limit=10&order_by=access_time:desc&is_accurate=0&data_source=1&host_state=2,1&alarm_sip=&attack_sip=&ioc=&asset_group=&threat_name=&attack_stage=&branch_id=&x_forwarded_for=&is_web_attack=&host=&status_http=&alarm_source=&staff_name=&uri=&alert_rule=&sip=&dip=&sport=&dport=&dst_mac=&src_mac=&vlan_id=&proto=&serial_num=&threat_type=&hazard_level=&status=&attck_org=&attck=&alarm_id=&attack_dimension=&is_white=0&focus_label=&marks=&asset_ip=&user_label=&start_time={}000&end_time={}999&csrf_token=xxxxxxxx&r=0.5742944888361291'.format(start_time, end_time)
    tianyan_req = requests.get(tianyan_url, headers=TianYan_HEADERS, verify=False)
    json_tianyan = json.loads(tianyan_req.text)
    return json_tianyan


def main():
    while True:
        json_yundun = yundun()
        json_tianyan = tianyan()

        print("当前查询时间：", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        # 云盾告警
        if json_yundun['code'] != "ConsoleNeedLogin":
            if json_yundun['data']["PageInfo"]["Count"] == 0:
                print("\n --> 云盾无紧急告警！\n")
            else:
                print("\n↙↙↙云盾紧急告警：↘↘↘")
                for i in json_yundun['data']['SuspEvents']:
                    alarm_name = i['AlarmEventName']
                    alarm_ip = i['IntranetIp']
                    print('告警 {} | IP：{}'.format(alarm_name, alarm_ip))
                print('-*' * 30, '\n')
        else:
            print("云盾Cookie过期！")
        
        # 天眼告警
        if json_tianyan['data']['total'] == 0:
            print(" --> 天眼无异常！")
        else:
            alarm_str = ""

            for i in json_tianyan['data']['items']:
                alarm_time = i['access_time']
                alarm_time = format_tstamp(alarm_time)
                alarm_name = i['threat_name']
                attack_ip = i['attack_sip']  # 攻击IP
                alarm_ip = i['alarm_sip']  # 受害IP
                sip_group = i['sip_group']  # 攻击资产组
                dip_group = i['dip_group']  # 受害资产组
                
                # 某些资产属组的告警不用管
                if sip_group == 'xxx' and dip_group == 'xxx' and alarm_name == '发现敏感信息泄露':
                    continue
                
                # 确定的 目的资产组没权管
                if dip_group in ["xxx", "xxx"]:
                    continue

                # 确定的 攻击IP不用管
                if attack_ip == "xxx.xxx.xxx.xx" and alarm_name == "发现脚本源码泄露":
                    continue
                alarm_str += '时间：{} | 告警：{} | 攻击IP：{} | 受害IP：{}\n'.format(alarm_time, alarm_name, attack_ip, alarm_ip)
            if alarm_str:
                print("↙↙↙天眼告警：↘↘↘")
                print(alarm_str)
            else:
                print("\n --> 天眼无异常告警！\n")
        
        # 亚信告警
        yaxin()
        
        print('-' * 60)
        time.sleep(Query_Interval)

    
if __name__ == "__main__":
    main()