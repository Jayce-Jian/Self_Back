CONFIG = {
        "yundun": {
                "Cookie": 'aliyun_lang=zh; aliyun_territory=CN; login_aliyunid=xxxxxxx'
            },
        "tianyan": {
                "Cookie": 'session=xxxxxxx'
            },
        "yaxin": {
                "Cookie": 'preCheckMFA=false; lastAccountName=; lastUsername=; sID=xxxxxx'
            },
        "query_interval": {
                "Interval": 300
            },
        "time_interval": {
                # 按天查询：昨天当前时间 和 今日当前时间 跨度
                # 按小时查询：时间跨度2小时，当前时间和2小时之前
                # day
                # hour
                "Interval": "hour"
            }
    }