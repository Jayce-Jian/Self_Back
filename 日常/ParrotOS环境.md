> ParrotOS环境

![https://i.loli.net/2020/07/24/omh6aOxfnIGDHWd.png](https://i.loli.net/2020/07/24/omh6aOxfnIGDHWd.png)

## 相关镜像，论坛

### 镜像

[官方镜像下载](https://www.parrotsec.org/download/)、[交大镜像下载](https://mirrors.sjtug.sjtu.edu.cn/parrot/iso/)、[清华镜像下载](https://mirrors.tuna.tsinghua.edu.cn/parrot/iso/)、[中科大镜像下载](https://mirrors.ustc.edu.cn/parrot/iso/)、[阿里云镜像下载](https://mirrors.aliyun.com/parrot/iso/)

### 论坛

[官方论坛](https://community.parrotsec.org/)、[国内论坛](https://parrotsec-cn.org/)

### 电报群

[官方TG群](https://t.me/parrotsecgroup)、[国内TG群](https://t.me/parrotsecCN)

### Discord讨论组

[ParrotSecCN](https://discord.com/invite/qWQdbPA8hz)

### Git库

[官方Gitlab](https://gitlab.com/parrotsec)、[官方Github](https://github.com/ParrotSec)、[国内Github](https://github.com/ParrotSec-CN/)

### QQ群

**群：638980158**

## 安装及分区

### 安装错误解决

**因为源都是在国外，所以在安装拉取源的时候，网络无法联通，这种情况下要修改sources-media文件**

- 提示：running command /usr/sbin/sources-media -u failed

    ```bash
    $ sudo vi /usr/sbin/sources-media
    
    屏蔽
    # rm $CHROOT /etc/apt/sources.list || true
    # mv $CHROOT /etc/apt/sources.list.orig $CHROOT /etc/apt/sources.list
    # mv $CHROOT /etc/apt/sources.list.parrot $CHROOT /etc/apt/sources.list.d/parrot.list
    
    或者
    
    # mv $CHROOT/etc/apt/sources.list $CHROOT/etc/apt/sources.list.orig
    # mv $CHROOT/etc/apt/sources.list.d/parrot.list $CHROOT/etc/apt/sources.list.parrot
    # echo "deb [trusted=yes] file://$MEDIUM_PATH $RELEASE main" > $CHROOT/etc/apt/sources.list
    ```

- 提示：/usr/sbin/sources-media-unmount 未能在 600 秒内完成

    ```bash
    $ sudo vi /usr/sbin/sources-media-unmount
    
    屏蔽
    # rm $CHROOT /etc/apt/sources.list || true
    # mv $CHROOT /etc/apt/sources.list.orig $CHROOT /etc/apt/sources.list
    # mv $CHROOT /etc/apt/sources.list.parrot $CHROOT /etc/apt/sources.list.d/parrot.list
    # chroot $CHROOT apt update || true
    
    或者
    
    # mv $CHROOT/etc/apt/sources.list $CHROOT/etc/apt/sources.list.orig
    # mv $CHROOT/etc/apt/sources.list.d/parrot.list $CHROOT/etc/apt/sources.list.parrot
    # echo "deb [trusted=yes] file://$MEDIUM_PATH $RELEASE main" > $CHROOT/etc/apt/sources.list
    ```
	
### 分区

```bash
/usr/share和/usr/local/share  #相当于C:/Program Files
/opt/  #相当于D盘，放置自己的软件

# 分区
/boot    btrfs
/        xfs
swap     swap
/home    btrfs
```

## 初始环境优化

### 更新bashrc文件

```bash
$ vi ~/.bashrc

# If you come from bash you might have to change your $PATH.
export PATH=~/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:$PATH

$ source .bashrc
```

### 修改更新源

```bash
$ sudo echo "" > /etc/apt/sources.list

$ sudo vi /etc/apt/source.list.d/parrot.list
```

```bash
# parrot repository
# 在source.list里面是deb和deb-src指向不同的软件库分类目录:一个是deb包的目录,一个是源码目录,不自己看程序或者编译,deb-src就不需要.
# 以下源任选其一

# 官方源
# Default Parrot Repository -> stable and tested.
deb https://deb.parrot.sh/parrot lory main contrib non-free non-free-firmware

# Security Updates -> this repo should always be enabled in your system.
deb https://deb.parrot.sh/parrot lory-security main contrib non-free non-free-firmware

# Backports -> disable it if you prefer stability and reliability over bleeding edge features.
#deb https://deb.parrot.sh/parrot lory-backports main contrib non-free non-free-firmware

# Updates / Testing -> mostly meant to be used by developers and beta testers.
#deb https://deb.parrot.sh/parrot lory-updates main contrib non-free non-free-firmware

# Source Code Repositories -> These repositories provide the debian source artifacts of the packages.
#deb-src https://deb.parrot.sh/parrot lory main contrib non-free non-free-firmware
#deb-src https://deb.parrot.sh/parrot lory-security main contrib non-free non-free-firmware
#deb-src https://deb.parrot.sh/parrot lory-backports main contrib non-free non-free-firmware
#deb-src https://deb.parrot.sh/parrot lory-updates main contrib non-free non-free-firmware

# 中科大源
# 默认中科大存储库 -> 稳定且经过测试.
deb http://mirrors.ustc.edu.cn/parrot lory main contrib non-free non-free-firmware

# 安全更新 -> 这个源应该一直在系统中启用.
deb http://mirrors.ustc.edu.cn/parrot lory-security main contrib non-free non-free-firmware

# 回退补丁 -> 如果你更喜欢稳定和可靠，而不喜欢激进更新的包源就禁用它.
#deb http://mirrors.ustc.edu.cn/parrot lory-backports main contrib non-free non-free-firmware

# 更新 / 测试 -> 主要用于开发和测试的工程师.
#deb http://mirrors.ustc.edu.cn/parrot lory-updates main contrib non-free non-free-firmware

# 源代码存储库 -> 这些存储库提供debian包的源文件.
#deb-src http://mirrors.ustc.edu.cn/parrot lory main contrib non-free non-free-firmware
#deb-src http://mirrors.ustc.edu.cn/parrot lory-security main contrib non-free non-free-firmware
#deb-src http://mirrors.ustc.edu.cn/parrot lory-backports main contrib non-free non-free-firmware
#deb-src http://mirrors.ustc.edu.cn/parrot lory-updates main contrib non-free non-free-firmware

# 清华源
# 默认清华存储库 -> 稳定且经过测试.
deb https://mirrors.tuna.tsinghua.edu.cn/parrot lory main contrib non-free non-free-firmware

# 安全更新 -> 这个源应该一直在系统中启用.
deb https://mirrors.tuna.tsinghua.edu.cn/parrot lory-security main contrib non-free non-free-firmware

# 回退补丁 -> 如果你更喜欢稳定和可靠，而不喜欢激进更新的包源就禁用它.
#deb https://mirrors.tuna.tsinghua.edu.cn/parrot lory-backports main contrib non-free non-free-firmware

# 更新 / 测试 -> 主要用于开发和测试的工程师.
#deb https://mirrors.tuna.tsinghua.edu.cn/parrot lory-updates main contrib non-free non-free-firmware

# 源代码存储库 -> 这些存储库提供debian包的源文件.
#deb-src https://mirrors.tuna.tsinghua.edu.cn/parrot lory main contrib non-free non-free-firmware
#deb-src https://mirrors.tuna.tsinghua.edu.cn/parrot lory-security main contrib non-free non-free-firmware
#deb-src https://mirrors.tuna.tsinghua.edu.cn/parrot lory-backports main contrib non-free non-free-firmware
#deb-src https://mirrors.tuna.tsinghua.edu.cn/parrot lory-updates main contrib non-free non-free-firmware

# 交大源
# 默认交大存储库 -> 稳定且经过测试.
deb https://mirrors.sjtug.sjtu.edu.cn/parrot lory main contrib non-free non-free-firmware

# 安全更新 -> 这个源应该一直在系统中启用.
deb https://mirrors.sjtug.sjtu.edu.cn/parrot lory-security main contrib non-free non-free-firmware

# 回退补丁 -> 如果你更喜欢稳定和可靠，而不喜欢激进更新的包源就禁用它.
#deb https://mirrors.sjtug.sjtu.edu.cn/parrot lory-backports main contrib non-free non-free-firmware

# 更新 / 测试 -> 主要用于开发和测试的工程师.
#deb https://mirrors.sjtug.sjtu.edu.cn/parrot lory-updates main contrib non-free non-free-firmware

# 源代码存储库 -> 这些存储库提供debian包的源文件.
#deb-src https://mirrors.sjtug.sjtu.edu.cn/parrot lory main contrib non-free non-free-firmware
#deb-src https://mirrors.sjtug.sjtu.edu.cn/parrot lory-security main contrib non-free non-free-firmware
#deb-src https://mirrors.sjtug.sjtu.edu.cn/parrot lory-backports main contrib non-free non-free-firmware
#deb-src https://mirrors.sjtug.sjtu.edu.cn/parrot lory-updates main contrib non-free non-free-firmware

# 阿里源
# 默认阿里存储库 -> 稳定且经过测试.
deb https://mirrors.aliyun.com/parrot lory main contrib non-free non-free-firmware

# 安全更新 -> 这个源应该一直在系统中启用.
deb https://mirrors.aliyun.com/parrot lory-security main contrib non-free non-free-firmware

# 回退补丁 -> 如果你更喜欢稳定和可靠，而不喜欢激进更新的包源就禁用它.
#deb https://mirrors.aliyun.com/parrot lory-backports main contrib non-free non-free-firmware

# 更新 / 测试 -> 主要用于开发和测试的工程师.
#deb https://mirrors.aliyun.com/parrot lory-updates main contrib non-free non-free-firmware

# 源代码存储库 -> 这些存储库提供debian包的源文件.
#deb-src https://mirrors.aliyun.com/parrot lory main contrib non-free non-free-firmware
#deb-src https://mirrors.aliyun.com/parrot lory-security main contrib non-free non-free-firmware
#deb-src https://mirrors.aliyun.com/parrot lory-backports main contrib non-free non-free-firmware
#deb-src https://mirrors.aliyun.com/parrot lory-updates main contrib non-free non-free-firmware
```

### 不更新burpsuite

- `$ sudo apt-mark hold burpsuite`

### (非必要) 系统更新脚本

- [更新脚本](https://github.com/ParrotSec-CN/ParrotOS-Script/blob/master/parrot-update)

`$ sudo mv parrot-update /usr/bin/parrot-update`

### 修改系统默认字符集

`$ sudo dpkg-reconfigure locales`

**选中zh_CN.UTF-8**

**如果没有中文字符集，则安装**

`$ sudo apt install locales-all -y`

**首选字符集选择zh_CN.UTF-8**

**重启系统，输入locale，检查字符集**

### (非必要) 清理系统残存配置

- `$ sudo dpkg -l |grep ^rc|awk '{print $2}' |sudo xargs dpkg -P`

### 清理系统软件包和内核

```bash
$ uname –r 查看正在使用的内核

$ sudo dpkg --get-selections | grep linux
```

**删除不用的内核文件image、头文件headers**

```bash
# sudo apt purge 内核文件名 头文件名

sudo apt purge linux-image-x.xx.x-xxxxx-amd64 linux-headers-x.xx.x-xxxxx-amd64 linux-headers-x.xx.x-xxxxx-common
```

**删除已下载的apt缓存**

- `sudo rm -rf /var/lib/apt/lists/`

### 添加i386支持

```bash
$ sudo dpkg --add-architecture i386

$ sudo apt update --fix-missing
```

### (非必要) 配置无密码sudoers

**查看当前用户所在组**

`$ groups`

```bash
$ sudo su

$ chmod u+w /etc/sudoers

$ vi /etc/sudoers

# User privilege specification
root  ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
# 把用户的组添加到sudo权限
%sudo ALL=(ALL:ALL) ALL
%user_groups ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

# includedir /etc/sudoers.d
# 用户使用sudo无需密码
user_name  ALL=(ALL) NOPASSWD:ALL

$ chmod u-w /etc/sudoers
```

### 增删用户
- 添加新用户

	```bash
	$ sudo useradd -m -G dialout,cdrom,floppy,sudo,audio,dip,video,plugdev,netdev,lpadmin,bluetooth,scanner tttx -s /bin/bash

	$ sudo passwd tttx
	```

- 查看其他用户占用的进程及删除用户

	```bash
	$ sudo ps -u 用户
	$ sudo kill -9 进程号  # 全部关闭
	$ sudo userdel 用户
	```

### 普通用户无法使用ping

- `$ sudo chmod u+s /bin/ping`

### 关闭IPV6

- NetWorkManager关闭IPV6

	```bash
	# 关闭/etc/resolv.conf的ipv6
	# 查看网卡连接
	$ nmcli connection show

	# 关闭IPV6
	$ nmcli con mod "Wired connection 1" ipv6.method ignore
	# $ nmcli con mod "有线连接 1" ipv6.method ignore
	# 或者
	$ nmcli con mod "Wired connection 1" ipv6.method "disabled"

	# 最后
	$ nmcli con up "Wired connection 1"
	# $ nmcli con up "有线连接 1"
	```

- sysctl.conf关闭IPV6

	```bash
	# 关闭/etc/sysctl.conf的ipv6
	$ sudo vi /etc/sysctl.conf
	
	# Disable IPV6
	# 关闭全部网卡的ipv6
	net.ipv6.conf.all.disable_ipv6 = 1
	# 关闭网卡eth0的ipv6
	# net.ipv6.conf.eth0.disable_ipv6 = 1
	# 关闭默认的ipv6
	net.ipv6.conf.default.disable_ipv6=1
	# 关闭本地环回的ipv6
	net.ipv6.conf.lo.disable_ipv6=1
	
	# 生效
	$ sudo sysctl -p
	```

### 更改国内时区

```bash
$ sudo rm /etc/localtime

$ sudo ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
```

### 更改桌面文件夹名称

*如：“桌面”改为“Desktop”*

```bash
$ export LANG=en_US

$ xdg-user-dirs-gtk-update
```

### 修改Proxychains配置

**解决’libproxychains.so.3’ from LD_PRELOAD cannot be preloaded**

*无法加载libproxychains.so.3库*

**正确文件位置**

```bash
$ whereis libproxychains.so.3

/usr/lib/x86_64-linux-gnu/libproxychains.so.3
```

**修改配置文件**

```bash
$ sudo vi /usr/bin/proxychains

export LD_PRELOAD=libproxychains.so.3

# 改为

export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libproxychains.so.3
```

**修改配置文件**

```bash
$ sudo vi /usr/lib/proxychains3/proxyresolv

DNS_SERVER=${PROXYRESOLV_DNS:-8.8.4.4}

export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libproxychains.so.3
```

**一键操作**

```bash
sudo sed -i 's/libproxychains.so.3/\/usr\/lib\/x86_64-linux-gnu\/libproxychains.so.3/' /usr/bin/proxychains

sudo sed -i 's/4.2.2.2/8.8.4.4/' /usr/lib/proxychains3/proxyresolv

sudo sed -i 's/libproxychains.so.3/\/usr\/lib\/x86_64-linux-gnu\/libproxychains.so.3/' /usr/lib/proxychains3/proxyresolv
```

## 配置SSH

### ①允许密码登录 和 root登录

`$ sudo vi /etc/ssh/sshd_config`

**取消#PasswordAuthentication yes的注释**

**将#PermitRootLogin prohibit-password，修改为PermitRootLogin yes**

### ②密钥登录

**修改配置文件，启用密钥登陆**

`$ sudo vi /etc/ssh/sshd_config`

```bash
PermitRootLogin no    # 取消root登录
RSAAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile  .ssh/authorized_keys .ssh/authorized_keys2

PasswordAuthentication no    # 取消密码认证
```

- **可以用Xshell生成密钥，把公钥写进~/.ssh/authorized_keys**
- **也可以用ssh-keygen生成密钥**
	- `ssh-keygen -t rsa -C "邮箱"`
- **把.pub公钥内容写入authorized_keys文件里面**
- `cat ~/.ssh/xxx.pub | xargs echo >> ~/.ssh/authorized_keys`
- **把私钥导入xshell**

### ③谷歌身份验证器

- [SSH使用谷歌身份验证器](https://trojanazhen.top/2019/10/18/2019-10-18_ssh_use_google_authenticator/)

### SSH开机自启动

**开启SSH服务**

- `sudo /etc/init.d/ssh start`

**开机自动启动SSH服务**

- `sudo update-rc.d ssh enable`

[SSH相关操作](https://trojanazhen.top/2018/12/26/2018-12-26_use_ssh/)

### 修改SSH提示信息

- `$ sudo vim /etc/motd`

[ASCII在线生成](https://www.ascii-art-generator.org/)

## 配置日常使用环境

```bash
$ sudo apt install libxml2 python-dev python-pip libxml2-dev libxslt1-dev zlib1g-dev libffi-dev libssl-dev tcl -y

$ sudo apt install gcc libpcre3 libpcre3-dev zlib1g zlib1g-dev openssl -y

$ sudo apt install tmux ipython3 fcitx fcitx-googlepinyin -y
```

### 安装Vim

- `$ sudo apt install vim -y`

**固定行号模式**

- `:set number`

**相对行号模式**

- `:set rnu`

**混合行号模式**

```bash
$ ~/.vimrc配置文件修改

set nu rnu

# vim内修改
:set nu | set rnu
```

### 配置VimPlus

[VimPlus](https://github.com/chxuan/vimplus)

```bash
$ git clone https://github.com/chxuan/vimplus.git ~/.vimplus && cd ~/.vimplus

# 安装vimplus
$ sudo ./install.sh

# 有时候ycm无法安装，所以先root试水
$ ./install.sh
```

**查找某些字符串**

- `find ~/.vim/  -name \* -type f -print | xargs grep "# coding=utf-8"`

**修改Python文件开头注释**

- `$ vi ~/.vim/plugged/prepare-code/snippet/snippet.py`

**更换颜色主题**

```bash
$ vi ~/.vimrc

" 主题
colorscheme peachpuff
```

**配置vim-Pep8**

[git地址](https://github.com/tell-k/vim-autopep8)

*问题解决：编译ycm提示要vim支持python/python3*

```bash
# 查看vim支持情况
$ vim --version

# 如果不支持python/pyhton3，删除vim以及所有依赖
$ dpkg -l | grep vim

$ sudo apt remove vim vim-common vim-runtime vim-xxx --purge -y

# 安装依赖
$ sudo apt install libncurses5-dev python3-dev -y

# 下载git最新的vim源码，然后编译
$ git clone https://github.com/vim/vim.git && cd vim

$ sudo ./configure --with-features=huge \
            --enable-multibyte \
            --enable-rubyinterp=yes \
            --enable-pythoninterp=yes \
            --with-python-config-dir=/usr/lib/python2.7/config-x86_64-linux-gnu \
            --enable-python3interp=yes \
            --with-python3-config-dir=/usr/lib/python3.8/config-3.8m-x86_64-linux-gnu \
            --enable-perlinterp=yes \
            --enable-luainterp=yes \
            --enable-gui=gtk2 --enable-cscope --prefix=/usr

$ sudo make VIMRUNTIMEDIR=/usr/share/vim/vim82

# 安装 vim
$ sudo make install

$ vim --version

# 之后再安装vimplus
```

**/usr/bin/vim替换/usr/bin/vi**

- `$ sudo ln -sf /usr/bin/vim /usr/bin/vi`

## 配置数据库

### 安装MySQL

**关闭MySQL服务**

- `sudo service mysql stop`

**启动mysql不使用密码和权限检查**

- `$ mysqld_safe --skip-grant-tables &`

**按回车继续连接MySQL**

- `$ sudo mysql -u root mysql`

**更新密码**

```bash
UPDATE user SET password=PASSWORD('新密码') WHERE user='root';`

FLUSH PRIVILEGES;

\q
```

**重启mysql服务**

- `$ sudo service mysql restart`

### 安装MariaDB

- `$ sudo apt install mariadb-server -y`

**开启SQL服务**

- `$ sudo service mysql start`

**初始化安全脚本设置Mariadb密码**

`$ sudo mysql_secure_installation`

```bash
# 新版本
- Enter current password for root    #直接回车(默认root是没有密码的)
- Switch to unix_socket authentication    #这个验证不需要密码不安全,输入n
- Change the root password    #输入n
- Remove anonymous users    #输入Y
- Disallow root login remotely    #输入Y
- Remove test database and access to it    #输入Y
- Reload privilege tables now    #输入Y
```

```bash
# 旧版本
- Enter current password for root    #直接回车(默认root是没有密码的)
- Set root password? [Y/n] Y
- New password： #设置新密码
- Re-enter new password:    #重复密码
- Remove anonymous users? [Y/n] Y
- Disallow root login remotely? [Y/n] Y
- Remove test database and access to it? [Y/n] Y
- Reload privilege tables now? [Y/n] Y
```

**旧版本修改非sudo可以登录数据库**

`$ sudo mysql -uroot -p`

```bash
MariaDB [(none)]> use mysql;
MariaDB [(none)]> update user set plugin='' where User='root';
MariaDB [(none)]> flush privileges;
MariaDB [(none)]> \q
```

**允许任意主机登录**

- `$ mysql -uroot -p`

- `grant all privileges on *.* to 'root'@'%' identified by '你的root密码' with grant option;`

- `flush privileges;`

**修改配置文件，屏蔽绑定本地ip**

```bash
$ sudo vi /etc/mysql/mariadb.conf.d/50-server.cnf

# bind-address = 127.0.0.1
```

**(MariaDB)修改数据库密码**

`$ sudo mysql -uroot -p`

```bash
use mysql;

update mysql.user set password=PASSWORD('新密码') where user='root';

flush privileges;
```

**(MySQL_5.7.19)修改数据库密码**

```bash
set password for 用户名@localhost = password('新密码');

flush privileges;
```

**重启mysql服务**

- `$ sudo service mysql restart`

*或者*

- `$ sudo /etc/init.d/mysql restart`

**允许外部链接数据库，查看端口占用情况**

- `$ netstat -ntlp | grep -v tcp6ps -aux | grep mysqld`

**杀掉进程id**

- `$ sudo kill -9 id`

**重启SQL服务**

### 配置Redis

> apt安装

- `$ sudo apt install redis-server -y`

**配置密码并允许外网访问**

`$ sudo vi /etc/redis/redis.conf`

```bash
requirepass 你的密码

bind 0.0.0.0 ::1
```

> 源码安装

**官方下载[稳定版](https://redis.io/download)并解压包**

- `$ wget http://download.redis.io/releases/redis-x.x.x.tar.gz  && tar -zxvf redis-x.x.x.tar.gz`

**复制并放到usr/local目录下**

- `$ sudo mv redis-x.x.x/ /usr/local/redis/`

**进入redis目录**

- `$ cd /usr/local/redis/`

**生成&测试&安装**

- `$ sudo make && sudo  make test && sudo make install`

**修改配置文件**

`$ vi ./redis.conf`

```bash
# 允许外网访问
bing 0.0.0.0
# 守护进程设置为yes
daemonize yes
# 数据文件
dbfilename dump.rdb
# 数据文件存储路径
dir /var/lib/redis
# 日志文件
logfile /var/log/redis/redis-server.log

# 设置密码
requirepass 你的密码
```

**把配置文件移动到/etc/目录下**

- `$ sudo cp ./redis.conf /etc/redis/`

**密码访问redis**

- `$ redis-cli -a 你的密码`

### 配置MongoDB

> apt安装

- `$ sudo apt install mongodb -y`

**配置密码访问**

- `$ sudo su`

- `$ mongo`

**使用admin库，创建root用户**

```bash
> use admin

> db.createUser({user: "root", pwd: "123456", roles:["root"]})
```

**启用认证开启mongo服务**

- `$ service mongodb stop`

- `$ mongod --auth --port 27017 --dbpath /var/lib/mongodb --bind_ip 0.0.0.0`

**启用root认证登陆mongo**

- `$ mongo 127.0.0.1:27017 -u "root" -p "123456" --authenticationDatabase "admin"`

**创建专属用户**

```bash
> use 数据库

> db.createUser({user: "cd2", pwd: "cd2", roles:["dbOwner"]})
```

**简单mongo客户端认证**

```bash
mongo

use 数据库

db.auth({"user":"cd2", "pwd":"cd2"})

show collections
```

> 源码安装

[官方下载](https://www.mongodb.com/download-center#community)**对应的包环境,解压压缩包**

- `$ wget xxx.tar.gz && tar -zxvf xxx.tar.gz`

**移动到/usr/local/目录下**

- `$ mv -r mongodb-linux-x86_64xxx/ /usr/local/share/mongodb`

**创建数据库文件夹**

- `$ sudo mkdir -p /data/db`

**添加用户环境变量**

- `$ vi ~/.bashrcexport PATH=/usr/local/share/mongodb/bin:$PATH`

**软链接可执行**

```bash
$ sudo ln -s /usr/local/share/mongodb/bin/mongod /usr/local/bin/mongodb
$ sudo ln -s /usr/local/share/mongodb/bin/mongod /usr/bin/mongodb

$ sudo ln -s /usr/local/share/mongodb/bin/mongo /usr/local/bin/mongo
$ sudo ln -s /usr/local/share/mongodb/bin/mongo /usr/bin/mongo
```

**启动mongodb服务**

- `$ mongodb`

**后台启动mongodb服务**

- `$ sudo /usr/local/share/mongodb/bin/mongod &`

*或者*

- `$ sudo nohup /usr/local/share/mongodb/bin/mongod > /home/haha/logs/log.log 2>&1 &`

**启动mongo**

- `$ mongo`

**解决Unable to create/open lock file: /data/db/mongod.lock errno:13 Permission denied**

```bash
$ sudo chmod 0755 /data/db

$ sudo chown `id -u` /data/db
```

[参考地址](https://blog.csdn.net/gcyxf/article/details/45502789)

**查看mongod后台进程**

- `$ ps -aux | grep mongod | grep -v grep | awk {'print $2'}`

### 配置Postgresql

**使用postgres用户打开psql**

- `$ sudo -u postgres psql`

**修改postgres用户（或数据库中其他用户）的密码**

- `\password postgres`

*或者*

- `\password myuser`

**退出pgsql**

- `\q`

---

## 配置uWSGI + Nginx

### 配置uWSGI

**安装uWSGI**

- `pip install uwsgi`

**配置uWSGI，在Django项目目录下创建uwsgi.ini文件**

```bash
[uwsgi]
# 使用nginx连接时使用
# socket=127.0.0.1:8080
# 直接做web服务器使用
http=127.0.0.1:8080
# 项目目录
chdir=/home/hacker/Desktop/Python/django
# 项目中wsgi.py文件的目录
wsgi-file=django/wsgi.py
processes=4
threads=2
master=True
pidfile=uwsgi.pid
daemonize=uswgi.log
```

**启动uWSGI**

- `$ uwsgi --ini uwsgi.ini`

**停止uWSGI**

- `$ uwsgi --stop uwsgi.pid`

**查看uWSGI进程**

- `$ ps ajx|grep uwsgi`

**如果uWSGI要配合Nginx使用，屏蔽uwsgi.ini文件里面的web服务器并去掉nginx的屏蔽**

```bash
# 使用nginx连接时使用
socket=127.0.0.1:8080
# 直接做web服务器使用
# http=127.0.0.1:8080
```

### 配置Nginx

> apt安装

```bash
$ sudo  sh -c 'echo "deb http://nginx.org/packages/mainline/debian/ stretch nginx\ndeb-src http://nginx.org/packages/mainline/debian/ stretch nginx" >> /etc/apt/sources.list.d/nginx.list'

$ wget -qO - http://nginx.org/keys/nginx_signing.key | sudo apt-key add - && sudo apt update &&

$ sudo apt remove nginx-common --purge -y

$ sudo apt install nginx -y
```

> 源码安装

**在nginx官网下载并安装稳定版[nginx](http://nginx.org/en/download.html)解包**

- `$ tar -zxvf nginx… … && cd nginx… …`

**编译**

- `$ ./config… …`

**安装**

`$ sudo make && sudo make install`

- 配合uWSGI使用

**修改配置文件**

- `$ sudo vi /etc/nginx/nginx.conf`

*Or*

- `$ sudo vi /usr/local/nginx/conf/nginx.conf`

*nginx配置文件/etc/nginx/nginx.conf，/etc/nginx/sites-enabled/default*

**在server节点下添加新的location项，指向uwsgi的ip与端口**

```bash
location /static {
    alias /var/www/django/static/;
}

location / {
    #将所有的参数转到uwsgi下
    include uwsgi_params;
    #uwsgi的ip与端口，如果是部署在远程服务器，如阿里云，一般绑定远程服务器内网ip
    uwsgi_pass 127.0.0.1:8080;
}
```

- uWSGI配合Nginx部署Django项目
  - `$ mkdir -vp /var/www/django/static/`

**修改目录权限**

- `$ chmod 777 /var/www/django/static/`

**修改项目里面的settings.py文件**

- `STATIC_ROOT='/var/www/django/static/'STATIC_URL='/static/'`

**收集所有静态文件到static_root指定目录**

- `$ python manage.py collectstatic`

**之后重启Nginx服务**

> nginx相关

**重新加载配置文件**

- `$ ./nginx -s reload`

**重启nginx**

- `$ ./nginx -s stop`

**查看端口占用情况**

- `$ netstat -ntpl`

*log错误，权限问题*

## 配置Python虚拟环境

### 安装独立的python

```bash
curl -O https://www.python.org/ftp/python/3.7.9/Python-3.7.9.tar.xz

tar -Jxvf Python-3.7.9.tar.xz

cd Python-3.7.9 && ./configure --enable-optimizations

make -j 1

# altinstall 独立环境，在原有安装基础上进行额外安装，可以让你在保持原有安装的基础上，额外安装一个或多个软件包
make altinstall
```

### pip源

- 本地持久化
  **更换清华pip源**`mkdir ~/.pip && cd ~/.pip && vi pip.conf`
  
    ```bash
    [global]
    index-url = https://pypi.tuna.tsinghua.edu.cn/simple
    ```
  
- 临时变量
`pip install -i https://pypi.tuna.tsinghua.edu.cn/simple bao`

### pip包导出，升级

- 导出
`pip freeze > xxx.txt`
- 导出关键包
  
    ```bash
    pip show 包名
    # "Requires: "是它的依赖包，导出包时，去掉它的依赖包
    ```
    
- 导入pip包

`pip install -r xxx.txt`

- 列出可升级的包

`pip list --outdate`

- 升级所有可升级的包

`pip freeze --local | grep -v '^\-e' | cut -d = -f 1 | xargs pip install -U`

### 安装poetry虚拟环境

`sudo pip install poetry --break-system-packages`

*or*

`curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python`

**部分食用方法**

```bash
# 新建py311项目
poetry new py311

# 在已有的项目里初始化Poetry
poetry init

# 指定创建虚拟环境使用的Python解释器版本
poetry env use python3

# 激活虚拟环境
poetry shell

# 向pyproject.toml中添加依赖
poetry add requests beautifulsoup4 numpy

# 移除依赖，也可以直接编辑pyproject.toml删除依赖项
poetry remove requests

# 存在pyproject.toml依赖文件，直接安装依赖环境
poetry install

# 查看当前依赖列表
poetry show --tree

# 导出依赖项
poetry export --dev -f requirements.txt --without-hashes > requirements.txt

# 清除所有缓存
poetry cache clear --all 
```

**换install源**

```bash
# 命令换源
poetry source add tsinghuapypi https://pypi.tuna.tsinghua.edu.cn/simple

# 或者修改pyproject.toml换源，添加为以下

[[tool.poetry.source]]
name = "tsinghuapypi"
url = "https://pypi.tuna.tsinghua.edu.cn/simple"
priority = "primary"

# 删除已配置的国内源
## 查看全局配置
poetry config

## 删除
命令删除：poetry config --unset repositories.tsinghuapypi
### 或者
文件删除：直接修改pyproject.toml文件删除配置的[[tool.poetry.source]]
```

**想复用同一个虚拟环境，就把pyproject.toml复制到项目里**

### 安装virtualenv虚拟环境及pep8

`sudo apt install python-virtualenv python3-dev -y`

`sudo pip3 install virtualenv virtualenvwrapper pep8 autopep8 pylint`

- 创建目录存放虚拟环境

`mkdir $HOME/.virtualenvs`

- 在用户环境变量~/.bashrc中添加：

  `vi ~/.bashrc`
  
    ```bash
    export WORKON_HOME=$HOME/.virtualenvs
    export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3
    source /usr/local/bin/virtualenvwrapper.sh
    ```
  
- 应用环境变量

`source ~/.bashrc` *or* `source ~/.zshrc`

- 创建并进入虚拟环境(Python3)

`mkvirtualenv 虚拟环境名`

- 提示OSError: … setuptools pkg_resources pip wheel failed with error code 1

`mv ~/.pip pip`

- 进入虚拟环境

`workon xxx`

#### 创建独立Py2虚拟环境

**相当于一个程序一个Py2的环境包**

`virtualenv -p /usr/bin/python2 venv-py27`

**进入环境**

`source ./venv-py27/bin/activate`

#### 创建workon Py2环境

- Error：“error: [Errno 13] Permission denied: ’/usr/local/lib/”就是sudo权限的问题
- 一种是直接sudo安装
- 另一种是把权限改成当前用户（current user）可写的模式
`$ sudo chown -R 'whoami' /usr/local/lib/python x`

**创建并进入虚拟环境(Python2)**

`$ mkvirtualenv -p /usr/bin/python2 Py2`

> 创建独立的Py3虚拟环境

`$ virtualenv -p /usr/bin/python3.7 venv-py37`

**进入环境**

`$ source ./venv-py37/bin/activate`

#### 利用venv创建独立的Py环境

```bash
$ apt -y install python3-pip python3-dev python3-venv

$ mkdir venv-Py3 && cd venv-Py3

$ python3 -m venv .

$ source ./venv-Py3/bin/activate
```

#### 找不到virtualenv命令

```bash
# 包地址：/usr/local/lib/python3.8/dist-packages/virtualenv
$ cat /usr/local/bin/virtualenv

#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys

from virtualenv.__main__ import run_with_catch

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(run_with_catch())
```

## 安装Tor浏览器

> apt安装

**写入tor源**

`$ sudo echo -e "deb https://deb.torproject.org/torproject.org stretch main\ndeb-src https://deb.torproject.org/torproject.org stretch main" >> /etc/apt/sources.list.d/tor.list`

**下载签名密钥**

`$ sudo proxychains wget -O- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | sudo apt-key add -`

**更新apt**

`$ sudo proxychains apt update --fix-missing`

**安装Tor**

`$ sudo proxychains apt install tor deb.torproject.org-keyring -y`

**安装Tor浏览器**

`$ proxychains torbrowser-launcher`

**运行Tor浏览器**

> 桌面图标

```bash
$ cp ~/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US/start-tor-browser.desktop ~/Desktop

$ vi ~/Desktop/start-tor-browser.desktop

# 修改X-TorBrowser-ExecShell
X-TorBrowser-ExecShell=proxychains sh /home/User/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US/Browser/start-tor-browser --detach

双击桌面图标启动Tor浏览器
```

## 安装Openjdk

[jdk.java.net](https://jdk.java.net/archive/)**下载：**

**解压后放到/usr/lib/jvm/下**

**修改终端持久化**

```bash
# /etc/profile和~/.bashrc

export JAVA_HOME=/usr/lib/jvm/java-xx-openjdk-amd64
export JRE_HOME=$JAVA_HOME/jre
export PATH=$JAVA_HOME/bin:$PATH
export CLASSPATH=.:$JAVA_HOME/lib:$JAVA_HOME/lib
```

## 配置部分安全软件

### BurpSuite

```bash
/usr/lib/jvm/java-21-openjdk-amd64/bin/java -XX:+IgnoreUnrecognizedVMOptions -javaagent:/opt/Burpsuite/BurpLoaderKeygen_v1.17.jar=loader, --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED --add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED --add-opens=java.base/jdk.internal.org.objectweb.asm.Opcodes=ALL-UNNAMED -Xmx2048m -jar /opt/Burpsuite/burpsuite_pro.jar
```

```bash
# Linux 激活信息保存位置
~/.java/.userPrefs/burp

# Windows 激活信息保存位置
HKEY_CURRENT_USER\Software\JavaSoft\Prefs\burp
```

### CobaltStrike

```bash
/usr/lib/jvm/java-13-openjdk-amd64/bin/java -XX:ParallelGCThreads=4 -XX:+AggressiveHeap -XX:+UseParallelGC -Xms512M -Xmx2048M -javaagent:/opt/CobaltStrike/cs491/Client/uHook.jar -Dfile.encoding=utf-8 -jar /opt/CobaltStrike/cs491/Client/cobaltstrike-client.jar
```

### 蚁剑

[github](https://github.com/AntSwordProject/AntSword-Loader)**下载AntSword-Loader**

```bash
$ unzip AntSword-Loader-v4.0.3-linux-x64.zip

$ mv AntSword-Loader-v4.0.3-linux-x64 AntSword-Loader

$ sudo mv AntSword-Loader /opt/
```

**[github](https://github.com/AntSwordProject/antSword)下载蚁剑**

```bash
$ git clone https://github.com/AntSwordProject/antSword.git

$ sudo mv antSword /opt/
```

**执行loader加载蚁剑**

`$ /opt/AntSword-Loader/AntSword`

### 冰蝎

[github](https://github.com/rebeyond/Behinder/releases)**下载冰蝎**

```bash
#!/bin/bash

cd /opt/Behinder
/usr/lib/jvm/java-8-openjdk-amd64/bin/java -jar /opt/Behinder/Behinder.jar
```

## (非必要) 安装中文字体

### 仅安装文泉驿字体

`$ sudo apt install ttf-wqy-microhei ttf-wqy-zenhei xfonts-wqy -y`

### 通用方法，只给当前用户安装（导致终端字体改变）

**在当前用户主目录下创建文件夹.fonts，把字体文件移动到里面**

`mkdir ~/.fonts`

**然后刷新字体信息文件**

`fc-cache -f -v`

### Debian的快捷方法（导致终端字体改变）

**安装Microsoft核心字体集**

`sudo apt install ttf-mscorefonts-installer`

**之后再把一些中文字体移动到/usr/share/fonts/truetype/目录下**

`sudo mv xxx /usr/share/fonts/truetype/`

## 配置Chromedriver

[**官网**](https://sites.google.com/a/chromium.org/chromedriver/downloads)

**下载解压Chromedriver**

`$ wget -N https://chromedriver.storage.googleapis.com/x.xx/chromedriver_linux64.zipunzip chromedriver_linux64.zip`

**添加执行权限**

`$ chmod +x chromedriver`

**添加软链接**

```bash
$ sudo mv -f chromedriver /usr/local/share/chromedriver

$ sudo ln -sf /usr/local/share/chromedriver /usr/local/bin/chromedriver

$ sudo ln -sf /usr/local/share/chromedriver /usr/bin/chromedriver
```

## 其他问题解决

### venv安装MySQL-python

*Command “python setup.py egg_info” failed*

- 安装依赖libmysqlclient18

[Debian官方](https://packages.debian.org/jessie/libmysqlclient18)

`$ sudo apt install libmysqlclient18`

- 安装依赖libmysqlclient-dev

[Debian官方](https://packages.debian.org/jessie/libmysqlclient-dev)

`$ sudo apt install libmysqlclient-devsudo apt --fix-broken install`

- 安装MySQL-python

`$ pip install MySQL-python`

### 无法联网

**更新所有软件，并更新系统之后，安装完所有环境，重启后，Parrot无法联网，可以ping通ip地址，但是无法ping通域名，dns解析出现问题**

**删掉原dns文件连接**

`$ rm -rf /etc/resolv.conf`

**新建并打开dns文件，添加下面内容**

`$ vi /etc/resolv.conf`

```bash
nameserver 8.8.8.8
nameserver 8.8.4.4

# 或者

nameserver 185.121.177.177
nameserver 169.239.202.202
nameserver 198.251.90.108
nameserver 198.251.90.109
nameserver 198.251.90.110
```

**重启网络**

`$ sudo service networking restart`

### 无法更新

**最近在公司遇到的, apt update, apt update –fix-missing报错**

`Clearsigned file isn't valid, got 'NOSPLIT' (does the network require authentication?)`

**经测试发现，用自己的wifi是可以更新的，so，源被公司给屏蔽掉了**

### 无法安装ipy2

**在python2的虚拟环境下安装ipython2，报错，提示Command “python setup.py egg_info”**

**提示信息，ipython6不支持python2，所以指定安装版本pip install ipython==5.5.0**

### Py2无法安装Pylint

**提示支持版本>=3.4**

`$ pip install pylint==1.9.3`

### 无法安装Tor的问题

**点击菜单栏的Tor browaser安装提示签名验证失败**

```bash
$ gpg --homedir "$HOME/.local/share/torbrowser/gnupg_homedir/" --refresh-keys --keyserver pool.sks-keyservers.net

$ sudo lsof -i:9040

$ sudo netstat -tunlp | grep 9040
```

### 相关uwsgi的问题

**Python3.7虚拟环境uwsgi安装失败**

`$ sudo apt install python3.7-dev -y`

**命令行启动uwsgi提示找不到so文件，UNABLE to load uWSGI plugin: ./python3x_plugin.so**

`$ sudo apt install uwsgi uwsgi-plugin-python uwsgi-plugin-python3 -y`

`$ cp /usr/lib/uwsgi/plugins/python3x_plugin.so ./`

### 右上角parrot menu不显示应用程序项目

`$ rm -rf ~/.config/menus`

### 控制中心丢失”网络连接”,“caja-actions-configuration-tool”

*修复”网络连接”*

`$ sudo apt install network-manager-gnome -y`

*修复”caja-actions-configuration-tool”*

`$ sudo apt install caja-actions -y`

### Dradis和beef-xss都占用3000端口

- 直接修改beef-xss的默认配置，换个端口

	- `sudo vi /etc/beef-xss/config.yaml`

### wrong ELF class: ELFCLASS64

`I think that xxx.o was compiled for 64-bit, and you are linking it with a 32-bit xxx.o.You can try to recompile xxx.c with the '-m64' flag of [gcc(1)](http://www.manpagez.com/man/1/gcc-3.3/)`
