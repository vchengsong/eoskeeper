


### 编写配置文件
mkdir -p /usr/lib/systemd/system 
vi /usr/lib/systemd/system/eoskeeper.service

### eoskeeper.service
``` 
[Unit]
Description=eoskeeper

[Service]
User=eosio
ExecStart=/bin/bash -c "/usr/local/bin/eoskeeper > /dev/null  2>&1"
Restart=always

[Install]
WantedBy=multi-user.target
```

### 操作
systemctl start eosio.service
systemctl stop eosio.service
systemctl enable eosio.service