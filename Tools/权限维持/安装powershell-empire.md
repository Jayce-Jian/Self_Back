> 安装powershell-empire

## 下载及安装
### 安装poetry
`sudo pip install poetry --break-system-packages`

### 安装mariadb
```bash
$ sudo apt install mariadb-server -y

# 启动服务
$ sudo service mysql start

# 初始化安全脚本
$ sudo mysql_secure_installation

- Enter current password for root    #直接回车(默认root是没有密码的)
- Switch to unix_socket authentication    #这个验证不需要密码不安全,输入n
- Change the root password    #输入n
- Remove anonymous users    #输入Y
- Disallow root login remotely    #输入Y
- Remove test database and access to it    #输入Y
- Reload privilege tables now    #输入Y
```

### 安装powershell-empire及Starkiller
[powershell-empire](https://github.com/BC-SECURITY/Empire)

[Starkiller](https://github.com/BC-SECURITY/Starkiller)

```bash
unzip Empire-main.zip

mv Empire-main powershell-empire

unzip Starkiller-main.zip

mv Starkiller-main Starkiller

mv Starkiller powershell-empire/empire/server/api/v2

sudo mv powershell-empire /usr/share/
```

### 安装.NET SDK
[.NET SDK](https://dotnet.microsoft.com/zh-cn/download/dotnet/6.0)

```bash
mkdir dotnet

mv dotnet-sdk-6.0.424-linux-x64.tar dotnet

tar -zxvf dotnet-sdk-6.0.424-linux-x64.tar

rm -rf dotnet-sdk-6.0.424-linux-x64.tar

chmod +x dotnet

sudo mv dotnet /usr/share/

sudo ln -sf /usr/share/dotnet/dotnet /usr/bin/
```

## 创建powershell-empire可执行文件

`touch powershell-empire`

`sudo mv powershell-empire /usr/bin/`

`sudo vi /usr/bin/powershell-empire`

```bash
#!/bin/bash
set -e

# Check if running as root
if [ `id -u` -ne 0 ]; then
   echo "Error: $0 must be run as root" 1>&2
   exit 1
fi

service mariadb start

# Check if the MySQL database empire exists.
# If the DB does not exist, it will create the DB, the DB user and the
# user password.
if ! mysqlshow "empire" > /dev/null 2>&1; then
    echo "Create mysql database empire"
    mysql -Bse "CREATE DATABASE empire;"
    mysql -Bse "CREATE USER empire_user@localhost IDENTIFIED BY 'empire_password';"
    mysql -Bse "GRANT ALL ON empire.* TO empire_user@localhost;"
    mysql -Bse "FLUSH PRIVILEGES;"
fi

cd /usr/share/powershell-empire
poetry run python3 empire.py ${@}
```

## 安装poetry环境

```bash
cd /usr/share/powershell-empire

sudo rm -rf poetry.lock

# 拉取依赖最好挂个代理，不然慢得要屎要屎的
sudo proxychains poetry install
```

## 启动

```bash
sudo powershell-empire server

sudo powershell-empire client
```