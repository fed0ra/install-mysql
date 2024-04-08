# install-mysql
安装mysql（单机、主从、mgr）

## 前提
修改脚本中的配置参数

## 单机安装
    bash -x ~/install-mysql8.sh

## 主从安装
    # 主库安装，需传输server-id，默认server-id=1
    bash -x ~/install-mysql8.sh 1

    # 从库安装，需传输server-id，且必须大于主库，如主库没传递参数，此处需大于1
    bash -x ~/install-mysql8.sh 2

    # 从库执行如下命令配置主从，repl后分别为主库的IP和端口
    bash -x ~/install-mysql8.sh repl 192.168.133.151 3306

## 单主mgr安装
    # mgr primary节点安装
    bash -x ~/install-mysql8.sh 1

    # mgr secondary1节点安装
    bash -x ~/install-mysql8.sh 2

    # mgr secondary2节点安装
    bash -x ~/install-mysql8.sh 3

    # 每个mgr节点执行如下命令配置mgr集群
    bash -x ~/install-mysql8.sh mgr
    bash -x ~/install-mysql8.sh mgr
    bash -x ~/install-mysql8.sh mgr

    # 查看成员信息
    select * from performance_schema.replication_group_members;
