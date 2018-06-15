# eoskeeper
EOS BP节点高可用守护进程

### 提示
如果您计划使用本程序，请仔细阅读源码eoskeeper.py。


### 已实现的功能
* 实时监控节点当前区块高度、不可逆块高度、当前出块BP名字。
* 实时监控BP节点是否正在出块。（1主2备使用相同的秘钥启动，需要通过过滤日志判断具体是哪个机器正在出块）
* 实时监控节点之间的p2p链接数量。（通过调用lsof命令实现，连接数是个非常重要的参数）
* 任何参数出现异常将会通过企业微信和短信报警。（需要使用您自己的微信和短信模块）
* 当主BP出现故障后，第一个备用BP在两轮后自动出块，实现BP的高可用。
* 如果主BP和第一个备用BP都故障无法出块，第二个备用BP在7轮后会开始出块，实现BP的高可用。
* 实时将各个节点的运行参数推送到influxdb，然后通过grafana进行展示。

其他：grafana界面，需要从influxdb数据库和zabbix数据库提取数据，并自行定制界面。

### 运行环境
python版本: 2.7  

### 安装于运行
```
安装
$ easy_install -U sh requests
$ mkdir /etc/eoskeeper 增加配置文件 vi /etc/eoskeeper/config.ini （参考config.ini）
$ 将eoskeeper.py的源码放到 /usr/local/bin/eoskeeper 文件中。
$ chmod +x /usr/local/bin/eoskeeper
$ 修改配置文件，关键是角色的修改。(角色的解释见下文，主BP角色为A，第一个备用BP角色为B，第二个备用BP角色为C，其他为F)

运行
建议使用systemctl 服务运行eoskeeper，创建服务请参考/systemctl/README.md
也可以eoskeeper，直接运行，运行前需要写好配置文件。

```

### 配置文件说明  
```a
role = "A"
block_producer_name = "eosstorebest"            # 注册的bp名称
eosio_log_file      = "/data/eosio.log"         # eosio日志文件
eoskeeper_log_file  = "/data/eoskeeper.log"     # eoskeeper本身
infulxdb_url        = "http://13.115.200.171:8086/write?db=eosdb"   # influxdb的url
mobiles             = "1821050****,1352131****"     #需要被短信通知的人员的手机号

```

### influxdb的两个表
BP节点表 （共3台机器）
表名 eosbpinfo  
字段名/中文名            属性          示例 
* host/主机名            (字符串)       eos-open-fn-1-1
* hbn/当前块             (整数)         19876
* lib/不可逆块            (整数)        19856
* linkn/连接数量          (整数)        34
* lpbt/上次出块时间     （字符串）        10秒前
* paused                 （字符串）     是
* info/告警信息         （字符串，最长60个字符） 
         

全节点表 （共7台机器）
表名 eosfninfo
* 字段名/中文名            属性          示例 
* host/主机名            (字符串)       eos-open-fn-1-1
* hbn/当前块             (整数)         19876
* lib/不可逆块            (整数)        19856
* linkn/连接数量          (整数)        34
* info/告警信息         （字符串，最长60个字符） 


### 逻辑说明

eoskeeper是一个用于监控eos程序的守护进程，并有报警和推送参数到influxdb的功能。

== 程序原理 ==  
我们的节点分为四种角色：A角色（BP）、B角色（备用BP，第一道防线）、C角色（备用BP，第二道防线）、普通全节点（后面用F角色表示）  
在三个主机中会分别给eoskeeper守护进程配置文件中设置为A、B、C三个角色，以下是eoskeeper根据角色做出相应的动作。  
当eosstorebest在前21名，B主机eosio运行正常，并且，B主机检测到2轮出块循环都没有eosstorebest账户时，B主机的eoskeeper会执行命令，使B出块。  
当eosstorebest在前21名，C主机eosio运行正常，并且，C主机检测到6轮出块循环都没有eosstorebest账户时，C主机的eoskeeper会执行命令，使C出块。    

== 配置相关 ==  
所有eosio需要配置 http-server-address = 127.0.0.1:8888  
为了/v1/producer/* api BP节点的eosio配置文件需增加 plugin = eosio::producer_api_plugin  

== 管理相关 ==  
任何一台主机出现故障时，都需要及时修复。修复后，使各个节点恢复自己的角色。  


### 相关命令
```bash
curl --request POST --url http://127.0.0.1:8888/v1/producer/pause
curl --request POST --url http://127.0.0.1:8888/v1/producer/resume
curl --request POST --url http://127.0.0.1:8888/v1/producer/paused
```