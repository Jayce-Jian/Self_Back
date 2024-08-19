**在v2subs.txt写入b64编码的订阅内容，启动脚本直接输出配置好的clash文件output.yaml**

**source_config.yaml为默认clash的config文件**

**clash_vmess_json.txt为clash vmess的json配置文件，毕竟我不想手动把可用的v2ray vmess转为clash vmess**

**如：**

```bash

- {'name': '🇺🇸104.20.25.146', 'type': 'vmess', 'server': '104.20.25.146', 'port': 2086, 'uuid': 'e9e3cc13-db48-4cc1-8c24-7626439a5339', 'alterId': 0, 'cipher': 'auto', 'udp': True, 'network': 'ws', 'ws-opts': {'path': 'github.com/Alvin9999', 'headers': {'Host': 'ip14.freegradely.xyz'}}}`

```

*目前输出vmess配置可用，其他能不能用？不清楚...*
