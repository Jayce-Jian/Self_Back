## **安装v2ray-core**

> **下载v2ray-core**

- [github:v2ray-core](https://github.com/v2fly/v2ray-core/releases/)

> **解压及创建usr/bin可执行**

- ```
  mkdir v2ray
  mv v2ray-linux-64.zip v2ray
  unzip v2ray-linux-64.zip
  cd .. && sudo mv v2ray/ /opt
  sudo chmod +x /opt/v2ray/v2ray
  sudo ln -sf /opt/v2ray/v2ray /usr/bin/
  ```

## **安装v2rayA**

> **下载v2rayA**

- [github:v2rayA](https://github.com/v2rayA/v2rayA/releases)

> **安装**

- `sudo dpkg -i installer_debian_x64_2.2.5.1.deb`


## **修改proxychains配置文件及DNS**

> **修改链接库**

- ```
  查看链接库位置
  
  $ whereis libproxychains.so.3
  
  $ /usr/lib/x86_64-linux-gnu/libproxychains.so.3
  ```

- ```
  $ sudo vi /usr/bin/proxychains
  
  export LD_PRELOAD=libproxychains.so.3
  # 改为
  export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libproxychains.so.3
  ```

> **修改DNS**

- ```
  $ sudo vi /usr/lib/proxychains3/proxyresolv
  
  DNS_SERVER=${PROXYRESOLV_DNS:-8.8.4.4}
  
  export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libproxychains.so.3
  ```

> **修改配置文件**

- ```
  $ sudo vi /etc/proxychains.conf
  
  socks5  127.0.0.1 20170
  ```
## **启动及使用v2rayA**

- ```
  $ sudo v2raya
  
  浏览器打开 http://localhost:2017/
  
  添加trojan/ss/ssr等链接，选择启用，然后点启动
  
  测试代理可用，sudo proxychains wget www.google.com
  ```
