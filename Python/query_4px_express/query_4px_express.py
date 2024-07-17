#!/usr/bin/python3
# -*- coding:utf-8 -*-
import json
import trackingmoreclass

from smtplib import SMTP_SSL
from email.header import Header
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr
from twilio.rest import Client

from Secrets import SECRETS


tracker = trackingmoreclass.track
result = ""
urlStr = ''


def _format_addr(s):
    name, addr = parseaddr(s)
    return formataddr((Header(name, 'utf-8').encode(), addr))


def send_email(express_infos):
    msg_from = SECRETS['mail']['from']
    passwd = SECRETS['mail']['passwd']
    msg_to = SECRETS['mail']['to']
    subject = '物流信息'
    words = '<html><h3>物流信息：<h4 style="color: blue">' \
            + express_infos + '</html></h3></h4>'

    # msg = MIMEText(mail_content, "plain", 'utf-8')
    msg = MIMEText(words, "html", 'utf-8')
    msg["Subject"] = Header(subject, 'utf-8')
    msg["From"] = _format_addr(u'您的物流信息 <%s>' % msg_from)
    msg["To"] = _format_addr(u'管理员 <%s>' % msg_to)

    try:
        # ssl登录
        smtp = SMTP_SSL('smtp.qq.com')
        # set_debuglevel()用来调试,1开启调试，0关闭调试
        smtp.set_debuglevel(0)
        smtp.ehlo('smtp.qq.com')
        smtp.login(msg_from, passwd)
        # Send_email
        smtp.sendmail(msg_from, msg_to, msg.as_string())
        print("Mail sent successfully!")
        smtp.quit()
    except Exception as e:
        print("Mail delivery failed!")


def real_time():
    urlStr = ""
    requestData = "{\"tracking_number\": \"DD190411288998\",\"carrier_code\":\"4px\",\"destination_code\":\"CN\",\"tracking_ship_date\": \"\",\"tracking_postal_code\":\"\",\"specialNumberDestination\":\"\",\"order\":\"\",\"order_create_time\":\"\",\"lang\":\"cn\"}"
    result = tracker.trackingmore(requestData, urlStr, "realtime")
    decode_str = result.decode()
    express_infos, express_email = "", ""
    if json.loads(decode_str)['meta']['code'] == 429:
        return("API请求过快，请二十分钟后再试!!!")
    elif json.loads(decode_str)['meta']['code'] == 200 and json.loads(decode_str)['meta']['type'] == 'Success' and json.loads(decode_str)['meta']['message'] == 'Success':
        json_str = json.loads(decode_str)
        express_infos = json_str['data']['items'][0]['lastEvent']
        express_time = json_str['data']['items'][0]['lastUpdateTime']
        express_email = express_time + " " + express_infos
    else:
        express_infos = '单号或查询有误!'
    return(express_infos, express_email)


def main():
    express_msg, express_email = real_time()
    express_msg = express_msg[0:8] + "..."
    send_email(express_email)

    # Your Account SID from twilio.com/console
    account_sid = SECRETS['twilio']['sid']
    # Your Auth Token from twilio.com/console
    auth_token  = SECRETS['twilio']['token']

    client = Client(account_sid, auth_token)

    message = client.messages.create(
            to=SECRETS['twilio']['to'], 
            from_=SECRETS['twilio']['from'],
            body=express_msg
    )

    print(message.sid)

if __name__ == '__main__':
    main()

