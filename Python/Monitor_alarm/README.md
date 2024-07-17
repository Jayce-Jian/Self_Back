# 需求

```bash
此次临时出差，就是因为甲方设备有点儿多，还非得来回 看看看看看
来回折腾太累了

直接把所有 已确认排除的告警排除掉，之后就是类似真实告警
折腾个脚本，一遍查全

肯定会有老哥给这玩意儿做成框架类的，但我懒，毕竟临时出差，除非我闲了

毕竟厂商产品越来越多。。。 。。。

当然真大厂肯定就用类似splunk的产品聚合这种东西了~
```

## config文件

```bash
必须的cookie

query_interval 睡眠时间
	配置文件是设置的5分钟

time_interval  时间跨度（比如查询一天内的，查询2小时内的）
	如果要修改指定的查询时间，需要修改time_function.py文件内的hours=-2
```

## 直接启动

`python main_alarm.py`

## 其他

**天眼和云盾 --> response返回是json数据**

**亚信 --> response返回是整个html**

## 安装依赖

`pip install -r requirements.txt`