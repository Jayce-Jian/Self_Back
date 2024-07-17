# Centos7 安装 码小六 Docker

## 安装mysql
`wget -i -c http://dev.mysql.com/get/mysql57-community-release-el7-10.noarch.rpm`

`yum -y install mysql57-community-release-el7-10.noarch.rpm`

`yum -y install mysql-community-server`

## 创建mysql用户

> 1. 查询安装后给的临时密码

`grep 'temporary password' /var/log/mysqld.log`

> 2.进入mysql
`mysql -uroot -p`

**输入密码**

> 3.更新密码（密码记得符合强度，可以带特殊字符）

`alter user user() identified by "woshimima@123";`

> 4.创建用于docker的用户tttx，密码为woshimima@123

`create user 'tttx'@'172.17.0.2' identified by 'woshimima@123';`

> 5.创建用于码小六的数据库code6

`create database code6;`

> 6.允许tttx用户访问172.17.0.2

`grant all on *.* to 'tttx'@'172.17.0.2';`

## centos 7安装docker和docker-compose

> 1.安装docker依赖

`yum install -y yum-utils device-mapper-persistent-data lvm2`

> 2.添加docker源

`yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo`

> 3.安装docker-ce

`yum install docker-ce`

> 4.安装docker-compose

```bash
curl -L https://github.com/docker/compose/releases/download/1.24.0-rc1/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
```

> 5.添加执行权限

`chmod +x /usr/local/bin/docker-compose`

> 6.启动docker

`systemctl start docker.service`

> 7.进入码小六文件夹

`cd code6-master`

## docker使用国内源

> 1.修改/etc/docker/daemon.json文件

`vi /etc/docker/daemon.json`

> 2.添加以下内容

```bash
{
  "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn"]
}
```

> 3.重新加载配置

`systemctl daemon-reload`

> 4.重启docker

`service docker restart`

> 5.创建docker镜像

`docker build -t code6 .`

## 启动code6

> 1.启动镜像（sql用户密码上面自己创建的）

```bash
docker run -d -p 666:80 -e MYSQL_HOST=172.17.0.1 -e MYSQL_PORT=3306 -e MYSQL_DATABASE=code6 -e MYSQL_USERNAME=tttx -e MYSQL_PASSWORD=woshimima@123 --name code6-server code6
```

> 2.进入镜像

`docker exec -it code6-server /bin/bash`

> 3.添加码小六用户

`php artisan code6:user-add tttx@tttx.com woshimima@123`

## 访问web端

[http://主机ip:666](http://主机ip:666)

