# query_4px_express

> 环境及依赖

```
# Python3

requests

twilio
```

> 一个小脚本

**简单的定时查询四方转运快递单号并发送最近的物流信息提醒到手机和邮箱**

> 最近在四方上海淘了些东西，闲着写个脚本

> 邮箱

**用的是QQ邮箱发送邮件，需要去QQ邮箱[申请第三方登录权限](https://mail.qq.com/)**

> 手机短信

**短信是[twilio](https://www.twilio.com/)免费的套餐**

**免费套餐，短信的中文字数限制在11个字**

> 快递查询

**接口用的是[trackingmore](https://my.trackingmore.com/cn.html)提供的，这个逗逼网站识别国内外ip，国内ip申请的api token只能在国内服务器使用，同理：国外申请的api token就只能在国外服务器上用，申请api的时候，注意你的网络环境**

**代码里的查询接口是用的实时模式，20分钟内只允许调用一次，你可以通过申请多个api去测试**

> 关键信息我已经从外部文件导入了

**Secrets.py**

```
SECRETS = {
    "twilio": {
        "sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxx",
        "token": "ffxxxxxxxxxxxxxxxxxxxxx",
        "to": "+86xxxxxxxx",
        "from": "+1xxxxxxxxxxx"
    },

    "mail": {
        "from": "xxxxxxx@qq.com",
        "passwd": "gjxxxxxxxxxxxxxxx",
        "to": "xxxxxxxxxxxxxxxx@hotmail.com"
        },

    "trackingmore": {
        "token": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        }
    }
```

> 相关

**代码58行，就是一个字典变字符串而已，不过trackingmore的写法非得加转义字符，不知道是什么鬼鸡儿，懒得改了**
