# -*- coding:utf-8 -*-
import time
import datetime


# 天眼
def time_timestamp(time_type):
    if time_type == 'day':
        # 2021-11-10 00:00:00
        # 2021-11-10 23:59:59
        tmp_time = time.strftime("%Y-%m-%d", time.localtime())
        start_time = tmp_time + " 00:00:00"
        end_time = tmp_time + " 23:59:59"
        start_timeArray = time.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end_timeArray = time.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        # 转换成时间戳
        start_timestamp = int(time.mktime(start_timeArray))
        end_timestamp = int(time.mktime(end_timeArray))
        return start_timestamp,end_timestamp
    elif time_type == 'hour':
        cutt_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        cutt_time = time.strptime(cutt_time, "%Y-%m-%d %H:%M:%S")
        
        sub_an_hour = (datetime.datetime.now()+datetime.timedelta(hours=-2)).strftime("%Y-%m-%d %H:%M:%S")
        sub_an_hour = time.strptime(sub_an_hour, "%Y-%m-%d %H:%M:%S")

        # 转换成时间戳
        start_timestamp = int(time.mktime(sub_an_hour))
        end_timestamp = int(time.mktime(cutt_time))
        return start_timestamp,end_timestamp


# 亚信
def time_format(time_type):
    if time_type == 'day':
        # 2021-11-10 00:00:00
        # 2021-11-10 23:59:59
        tmp_time = time.strftime("%Y-%m-%d", time.localtime())
        start_time = tmp_time + " 00:00:00"
        end_time = tmp_time + " 23:59:59"
        return start_time,end_time
    elif time_type == 'hour':
        cutt_time = time.strftime("%Y-%m-%d %H:%M", time.localtime())
        
        sub_an_hour = (datetime.datetime.now()+datetime.timedelta(hours=-2)).strftime("%Y-%m-%d %H:%M")
        sub_an_hour = time.strptime(sub_an_hour, "%Y-%m-%d %H:%M")
        sub_an_hour = time.strftime("%Y-%m-%d %H:%M", sub_an_hour)

        return sub_an_hour, cutt_time
        
