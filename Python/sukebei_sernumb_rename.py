#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# 车：https://sukebei.nyaa.si/?f=0&c=0_0&q=%E6%A5%B5%E5%93%81%E8%BB%8A%E7%89%8C

import os
import re
import shutil

re_names = []

SN_PATH = '/home/xxxx/Desktop/Serial_number'


def read_file_rename(file_path, root_path, name):
    with open(file_path,'r') as file_data:
        tmp_data = "".join(x for x in file_data.readlines()[0:6])
        tmp_name = re.search(r'name[a-zA-Z0-9]+:(\[.*?\]?)?([a-zA-Z0-9\-]+\-?[a-zA-Z0-9\-]+)', tmp_data)
        tmp_name = tmp_name.group()
        tmp_file_name = tmp_name.split(":")[1:][0]
        print("种子文件名：", tmp_file_name)
        if name[:-8] == tmp_file_name:
            print("当前文件无需修改!\n")
        else:
            if tmp_file_name not in re_names:
                os.rename(file_path, root_path+'/'+tmp_file_name+'.torrent')
                re_names.append(tmp_file_name)
            else:
                # 目录下已存在同文件名的种子，移动到其他文件夹
                shutil.move(file_path, root_path[:-13]+"bak")


for root, dirs, files in os.walk(SN_PATH, topdown=False):
    for name in files:
        # 正常用工具在sukebei下载的种子是全数字名
        print("当前文件名：", name)
        tmp_file_path = os.path.join(root, name)
        read_file_rename(tmp_file_path, root, name)
