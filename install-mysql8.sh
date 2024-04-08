#!/bin/bash

# mysql版本
mysql8_version_dir="mysql-8.0.28-linux-glibc2.12-x86_64"
mysql8_version="$mysql8_version_dir.tar.xz"

# 下载
#cd ~ && wget https://cdn.mysql.com/archives/mysql-8.0/$mysql8_version

# root密码
root_passwd="Admin@2023"

# 同步复制用户密码
repl_user="repl"
repl_passwd="Repl@2023"

# 8.0克隆用户密码
clone_user="clone_user"
clone_passwd="Clone@2023"

# mgr组复制配置
mgr1_primary_ip=192.168.133.151       # mgr primary节点节点IP
mgr2_secondary_ip=192.168.133.152     # mgr secondary节点IP
mgr3_secondary_ip=192.168.133.153     # mgr secondary节点IP

mgr_port=33061       # mgr节点通讯端口

nic=ens32       # 网卡，修改为自己主机网卡
local_ip=`ip addr show $nic | grep -oP '(?<=inet\s)\d+(\.\d+){3}'`

if ! grep -w '# The mgr hosts' /etc/hosts &>/dev/null;then
cat >> /etc/hosts << 'EOF'
# The mgr hosts
192.168.133.151 hdss133-151.host.com
192.168.133.152 hdss133-152.host.com
192.168.133.153 hdss133-153.host.com
EOF
fi
############################以下不用修改############################
if [ "$1" = "repl" ];then
        if [ "$#" = 3 ];then
master_ip=$2
master_port=$3
mysql -S /usr/local/mysql/mysql.sock -u root -P 3306 -p$root_passwd --connect-expired-password -e "CHANGE MASTER TO MASTER_HOST = '$master_ip', MASTER_USER = '$repl_user', MASTER_PORT = $master_port, MASTER_PASSWORD = '$repl_passwd', master_auto_position=1,MASTER_CONNECT_RETRY=10;START SLAVE;"
echo "MySQL主从复制同步已经初始化完毕。"
exit 0
else
echo "Usage: $0 repl <master_ip> <master_port>"
exit 1
fi
fi

if [ "$1" = "mgr" ];then
        if [[ -z $local_ip ]];then
                echo "Error: 获取不到主机IP，修改脚本nic为主机网卡"
                exit 0
        fi
                sed -i "s|^#loose_group_replication_local_address=.*|loose_group_replication_local_address=$local_ip:${mgr_port}|g" /usr/local/$mysql8_version_dir/my.cnf
                sed -i "s|^#loose_group_replication_group_seeds=.*|loose_group_replication_group_seeds=${mgr1_primary_ip}:${mgr_port},${mgr2_secondary_ip}:${mgr_port},${mgr3_secondary_ip}:${mgr_port}|g" /usr/local/$mysql8_version_dir/my.cnf

        if [ "$local_ip" = "$mgr1_primary_ip" ];then
                mysql -S /usr/local/mysql/mysql.sock -u root -P 3306 -p$root_passwd --connect-expired-password -e "set persist group_replication_local_address =  '${local_ip}:${mgr_port}'; set persist group_replication_group_seeds = '${mgr1_primary_ip}:${mgr_port},${mgr2_secondary_ip}:${mgr_port},${mgr3_secondary_ip}:${mgr_port}';SET GLOBAL group_replication_bootstrap_group=ON; CHANGE MASTER TO MASTER_USER='$repl_user',MASTER_PASSWORD='$repl_passwd' FOR CHANNEL 'group_replication_recovery';START GROUP_REPLICATION;select sleep(5);select * from performance_schema.replication_group_members;SET GLOBAL group_replication_bootstrap_group=OFF;"
                echo "MySQL Mgr组复制已经初始化完毕。"
                exit 0
        else                
                mysql -S /usr/local/mysql/mysql.sock -u root -P 3306 -p$root_passwd --connect-expired-password -e "set persist group_replication_local_address =  '${local_ip}:${mgr_port}'; set persist group_replication_group_seeds = '${mgr1_primary_ip}:${mgr_port},${mgr2_secondary_ip}:${mgr_port},${mgr3_secondary_ip}:${mgr_port}'; SET GLOBAL group_replication_bootstrap_group=OFF; CHANGE MASTER TO MASTER_USER='$repl_user',MASTER_PASSWORD='$repl_passwd' FOR CHANNEL 'group_replication_recovery';START GROUP_REPLICATION;select sleep(5);select * from performance_schema.replication_group_members;"                          
                echo "MySQL Mgr组复制已经初始化完毕。"
                exit 0
        fi
fi

sys=`cat /etc/os-release | grep -w "ID" | awk -F "=" '{print $2}'`
if [ "$sys" = "ubuntu" ] || [ "$sys" = "debian" ];then	# For Ubuntu
	apt-get install expect libnuma1 libtinfo5 -y && ldconfig
elif [ "$sys" = "centos" ] || [ "$sys" = "fedora" ] || [ "$sys" = "rhel" ];then	# For CentOS
	yum -y install expect numactl* jemalloc* libaio*
fi


useradd mysql -r -s /sbin/nologin

tar xf ~/$mysql8_version

mv ~/$mysql8_version_dir /usr/local/

cd /usr/local/$mysql8_version_dir

mkdir -p /data/mysql/data
mkdir -p /data/mysql/log
mkdir -p /data/mysql/relaylog
mkdir -p /data/mysql/binlog
chown -R mysql.mysql /data/mysql

# 配置文件(8.0.28)
cat > my.cnf << 'EOF'
[client]
port=3306
socket=/usr/local/mysql/mysql.sock

[mysql]
socket=/usr/local/mysql/mysql.sock

[mysqld]
user=mysql
port=3306
basedir=/usr/local/mysql
datadir=/data/mysql/data
socket=/usr/local/mysql/mysql.sock
pid-file=/usr/local/mysql/mysqld.pid
admin_address='127.0.0.1'
admin_port=33062
log_error=/data/mysql/log/error.log
default_time_zone='+8:00'
# 关闭mysql-8默认的33060端口
mysqlx=0
# slow log
slow_query_log=ON
slow_query_log_file=/data/mysql/log/mysql-slow.log
long_query_time=1

# 主从配置
server-id=1# 从2
read-only=0# 从1
skip-name-resolve
log-bin=/data/mysql/binlog/binlog
binlog_format=ROW
binlog_row_image=FULL
binlog_row_metadata=FULL
binlog_checksum=NONE	# CRC32
binlog_cache_size=1M
binlog_rows_query_log_events=OFF
binlog_transaction_dependency_tracking=WRITESET
binlog_stmt_cache_size=32768
binlog_transaction_dependency_history_size=500000
binlog_order_commits=OFF
expire_logs_days=10
log_bin_trust_function_creators=1
master-info-repository=TABLE
relay-log=/data/mysql/relaylog/relay-log
relay-log-info-repository=TABLE

# gtid配置
gtid_mode=ON
enforce_gtid_consistency=1
log-slave-updates=1

# mgr配置
loose_transaction_write_set_extraction=XXHASH64
loose_group_replication_start_on_boot=ON  # 是否随mysql启动Group Replication
loose_group_replication_bootstrap_group=OFF # 是否是Group Replication的引导节点，初次搭建集群的时候需要有一个节点设置为ON来启动Group Replication，参数设置为ON，是为了标示以后加入集群的服务器都已这台服务器为基准。以后加入的就不需要进行设置
loose_group_replication_group_name=34975c79-405c-11eb-9f4c-5254044caef1
#loose_group_replication_local_address=192.168.148.41:33061       
#loose_group_replication_group_seeds=192.168.148.41:33061,192.168.148.42:33072,192.168.148.39:33083       
loose_group_replication_single_primary_mode=ON
loose_group_replication_exit_state_action =OFFLINE_MODE
loose_group_replication_transaction_size_limit=150000000 # 默认143M事务大小，最大值2147483647（大约2G），当此系统变量设置为0时，该组接受的事务大小没有限制。
loose_group_replication_enforce_update_everywhere_checks=OFF # 在单主模式下设置为OFF，多主模式下设置为ON。

loose_group_replication_flow_control_member_quota_percent=0
loose_group_replication_flow_control_min_quota=0
loose_group_replication_flow_control_mode=DISABLED
loose_group_replication_flow_control_min_recovery_quota=0
loose_group_replication_flow_control_certifier_threshold=25000
loose_group_replication_flow_control_applier_threshold=25000
loose_group_replication_flow_control_release_percent=50
loose_group_replication_flow_control_period=1
loose_group_replication_flow_control_hold_percent=10
loose_group_replication_transaction_size_limit=150000000
innodb_adaptive_max_sleep_delay=150000
innodb_adaptive_hash_index=OFF
innodb_adaptive_flushing_lwm=10
innodb_adaptive_flushing=ON
innodb_autoextend_increment=64
innodb_autoinc_lock_mode=2
innodb_buffer_pool_load_at_startup=ON
innodb_buffer_pool_dump_pct=25
innodb_buffer_pool_instances=8
innodb_buffer_pool_dump_at_shutdown=ON
#innodb_buffer_pool_size={DBInstanceClassMemory*3/4}
innodb_compression_pad_pct_max=50
innodb_compression_level=6
innodb_compression_failure_threshold_pct=5
innodb_change_buffer_max_size=25
innodb_change_buffering=all
innodb_commit_concurrency=0
innodb_checksum_algorithm=crc32
innodb_concurrency_tickets=5000
innodb_cmp_per_index_enabled=OFF
#innodb_data_file_purge_max_size=128
#innodb_data_file_purge=ON
#innodb_data_file_purge_interval=100
innodb_disable_sort_file_cache=OFF
innodb_deadlock_detect=ON
innodb_flush_method=O_DIRECT
innodb_flush_log_at_trx_commit=2
innodb_flush_sync=ON
innodb_flush_neighbors=0
innodb_ft_enable_stopword=ON
innodb_ft_enable_diag_print=OFF
innodb_ft_result_cache_limit=2000000000
innodb_ft_max_token_size=84
innodb_ft_sort_pll_degree=2
innodb_ft_total_cache_size=640000000
innodb_ft_cache_size=8000000
innodb_ft_min_token_size=3
innodb_ft_num_word_optimize=2000
innodb_io_capacity_max=40000
innodb_io_capacity=20000
innodb_log_compressed_pages=OFF
innodb_log_checksums=ON
innodb_log_file_size=1500M
innodb_lock_wait_timeout=50
#innodb_lru_scan_depth={LEAST(DBInstanceClassMemory/1048576/8, 8192)}
innodb_max_purge_lag=0
innodb_max_purge_lag_delay=0
innodb_max_dirty_pages_pct=75
innodb_max_dirty_pages_pct_lwm=0
innodb_max_undo_log_size=1073741824
innodb_monitor_disable=
innodb_monitor_enable=
innodb_old_blocks_time=1000
innodb_old_blocks_pct=37
innodb_online_alter_log_max_size=134217728
innodb_optimize_fulltext_only=OFF
#innodb_open_files={LEAST(DBInstanceClassCPU*500, 8000)}
innodb_print_all_deadlocks=OFF
innodb_purge_rseg_truncate_frequency=128
innodb_purge_batch_size=300
innodb_page_cleaners=8
#innodb_purge_threads={LEAST(DBInstanceClassMemory/1073741824, 8)}
innodb_rollback_segments=128
innodb_rollback_on_timeout=OFF
innodb_read_ahead_threshold=56
innodb_read_io_threads=4
innodb_random_read_ahead=OFF
innodb_sync_array_size=1
innodb_sync_spin_loops=30
innodb_stats_transient_sample_pages=8
innodb_stats_auto_recalc=ON
innodb_stats_on_metadata=OFF
innodb_stats_persistent_sample_pages=20
innodb_stats_method=nulls_equal
innodb_stats_persistent=ON
innodb_status_output=OFF
innodb_status_output_locks=OFF
innodb_strict_mode=OFF
innodb_sort_buffer_size=1048576
innodb_spin_wait_delay=6
innodb_thread_concurrency=0
innodb_thread_sleep_delay=10000
innodb_table_locks=ON
innodb_write_io_threads=4
loose_innodb_numa_interleave=ON
loose_innodb_log_write_ahead_size=4096
loose_innodb_parallel_read_threads=1
loose_innodb_doublewrite_pages=64
loose_performance_schema_accounts_size=0
loose_performance_schema_digests_size=0
loose_performance_schema_events_statements_history_size=0
loose_performance_schema_events_statements_history_long_size=0
loose_performance_schema_events_transactions_history_size=0
loose_performance_schema_events_transactions_history_long_size=0
loose_performance_schema_events_stages_history_long_size=0
loose_performance_schema_events_stages_history_size=0
loose_performance_schema_events_waits_history_long_size=0
loose_performance_schema_events_waits_history_size=0
loose_performance_schema_error_size=0
loose_performance_schema_hosts_size=0
loose_performance_schema_max_cond_classes=0
loose_performance_schema_max_cond_instances=0
loose_performance_schema_max_digest_sample_age=0
loose_performance_schema_max_digest_length=0
loose_performance_schema_max_file_instances=0
loose_performance_schema_max_file_handles=0
loose_performance_schema_max_index_stat=0
loose_performance_schema_max_mutex_classes=0
loose_performance_schema_max_mutex_instances=0
loose_performance_schema_max_memory_classes=0
loose_performance_schema_max_metadata_locks=0
loose_performance_schema_max_rwlock_instances=0
loose_performance_schema_max_stage_classes=0
loose_performance_schema_max_statement_classes=0
loose_performance_schema_max_socket_classes=0
loose_performance_schema_max_socket_instances=0
loose_performance_schema_max_thread_instances=0
loose_performance_schema_max_thread_classes=0
loose_performance_schema_max_table_lock_stat=0
loose_performance_schema_max_table_handles=0
loose_performance_schema_max_table_instances=0
loose_performance_schema_session_connect_attrs_size=0
loose_information_schema_stats_expiry=86400
loose_performance_schema_setup_actors_size=0
loose_performance_schema_setup_objects_size=0
loose_performance_schema_users_size=0
loose_performance_schema_max_rwlock_classes=0
loose_performance_schema_max_program_instances=0
loose_performance_schema_max_file_classes=0
loose_performance_schema_max_statement_stack=0
loose_performance_schema_max_sql_text_length=0
loose_performance_schema_max_prepared_statements_instances=0
loose_optimizer_trace_features=greedy_search=on,range_optimizer=on,dynamic_range=on,repeated_subselect=on
loose_optimizer_switch=index_merge=on,index_merge_union=on,index_merge_sort_union=on,index_merge_intersection=on,engine_condition_pushdown=on,index_condition_pushdown=on,mrr=on,mrr_cost_based=on,block_nested_loop=on,batched_key_access=off,materialization=on,semijoin=on,loosescan=on,firstmatch=on,subquery_materialization_cost_based=on,use_index_extensions=on
loose_optimizer_trace=enabled=off,one_line=off
loose_internal_tmp_mem_storage_engine=MEMORY
ft_query_expansion_limit=20
ft_min_word_len=4
ft_max_word_len=84
bulk_insert_buffer_size=4194304
show_old_temporals=OFF
thread_stack=1048576
thread_cache_size=100
optimizer_search_depth=62
optimizer_prune_level=1
optimizer_trace_max_mem_size=16384
optimizer_trace_offset=-1
optimizer_trace_limit=1
max_connections=2520
max_execution_time=0
max_sort_length=1024
max_binlog_cache_size=18446744073709547520
max_binlog_stmt_cache_size=18446744073709547520
max_allowed_packet=1073741824
max_length_for_sort_data=1024
max_heap_table_size=67108864
max_connect_errors=100
max_seeks_for_key=18446744073709500000
max_points_in_geometry=65536
max_prepared_stmt_count=16382
max_sp_recursion_depth=0
max_join_size=18446744073709551615
max_user_connections=2000
max_error_count=64
max_write_lock_count=102400
init_connect=''
event_scheduler=ON
avoid_temporal_upgrade=OFF
end_markers_in_json=OFF
disconnect_on_expired_password=ON
explicit_defaults_for_timestamp=OFF
sql_mode=ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION
sql_require_primary_key=OFF
range_optimizer_max_mem_size=8388608
range_alloc_block_size=4096
slave_net_timeout=60
slave_parallel_type=LOGICAL_CLOCK
slave_type_conversions=
wait_timeout=86400
transaction_isolation=READ-COMMITTED
transaction_write_set_extraction=XXHASH64
transaction_alloc_block_size=8192
transaction_prealloc_size=4096
updatable_views_with_limit=YES
local_infile=ON
flush_time=0
key_cache_division_limit=100
key_cache_age_threshold=300
key_cache_block_size=1024
stored_program_cache=256
group_concat_max_len=1024
back_log=3000
min_examined_row_limit=0
default_week_format=0
default_storage_engine=InnoDB
default_authentication_plugin=mysql_native_password
auto_increment_offset=1
auto_increment_increment=1
character_set_server=utf8
character_set_filesystem=binary
host_cache_size=644
lc_time_names=en_US
table_open_cache_instances=16
sync_master_info=10000
sync_relay_log_info=10000
sync_binlog=1000
mysql_native_password_proxy_users=OFF
query_alloc_block_size=8192
query_prealloc_size=8192
slow_launch_time=2
eq_range_index_dive_limit=100
connect_timeout=10
div_precision_increment=4
lock_wait_timeout=31536000
ngram_token_size=2
tmp_table_size=2097152
interactive_timeout=7200
open_files_limit=655350
temptable_max_ram=1073741824
automatic_sp_privileges=ON
delay_key_write=ON
general_log=OFF
lower_case_table_names=0
sha256_password_proxy_users=OFF
delayed_insert_timeout=300
delayed_insert_limit=100
delayed_queue_size=1000
preload_buffer_size=32768
concurrent_insert=1
block_encryption_mode="aes-128-ecb"
net_buffer_length=16384
net_read_timeout=30
net_retry_count=10
net_write_timeout=60
session_track_gtids=OFF
myisam_sort_buffer_size=262144
performance_schema={LEAST(DBInstanceClassMemory/8589934592, 1)}
join_buffer_size=1M
master_verify_checksum=OFF
log_bin_use_v1_row_events=1
log_slow_admin_statements=OFF
log_error_verbosity=3
log_throttle_queries_not_using_indexes=0
log_queries_not_using_indexes=OFF
low_priority_updates=0
sort_buffer_size=2M
read_buffer_size=1M
#tls_version=TLSv1,TLSv1.1,TLSv1.2
#table_open_cache={LEAST(DBInstanceClassMemory/1073741824*512, 8192)}
#table_definition_cache={LEAST(DBInstanceClassMemory/1073741824*512, 8192)}
#performance_point_iostat_volume_size=10000
#performance_point_iostat_interval=2
#performance_point_lock_rwlock_enabled=ON
#opt_tablestat=OFF
#opt_indexstat=OFF

# unknown variable
#loose_recycle_scheduler=OFF
#loose_ccl_queue_hot_delete=OFF
#loose_rds_audit_log_event_buffer_size=8192
#loose_innodb_rds_flashback_task_enabled=OFF
#loose_recycle_bin=OFF
#loose_json_document_max_depth=100
#loose_binlog_parallel_flush=OFF
#loose_innodb_undo_retention=0
#loose_innodb_rds_faster_ddl=ON
#loose_thread_pool_size=1
#loose_opt_rds_last_error_gtid=ON
#loose_thread_pool_enabled=ON
#loose_persist_binlog_to_redo=OFF
#loose_ccl_queue_hot_update=OFF
#loose_recycle_bin_retention=604800
#loose_opt_rds_enable_show_slave_lag=ON
#loose_validate_password_length=8
#loose_force_memory_to_innodb=OFF
#loose_multi_blocks_ddl_count=0
#loose_innodb_undo_space_reserved_size=0
#loose_innodb_log_optimize_ddl=OFF
#loose_innodb_rds_chunk_flush_interval=100
#loose_innodb_undo_space_supremum_size=10240
#loose_sql_safe_updates=OFF
#loose_ccl_queue_bucket_count=4
#loose_ignore_index_hint_error=OFF
#loose_innodb_rds_free_resize=ON
#loose_group_replication_flow_control_max_commit_quota=0
#loose_ccl_queue_bucket_size=64
#loose_innodb_trx_resurrect_table_lock_accelerate=OFF
#loose_thread_pool_oversubscribe=32
EOF

if [[ $1 = 1 ]];then
        sed -i "s|^server-id=.*|server-id=$1|g" /usr/local/$mysql8_version_dir/my.cnf
elif [[ $1 =~ ^[2-9]+$ ]]; then
        sed -i "s|^server-id=.*|server-id=$1|g" /usr/local/$mysql8_version_dir/my.cnf
        sed -i "s|^read-only=.*|read-only=1|g" /usr/local/$mysql8_version_dir/my.cnf
else
	echo "Usage: $0 1~9"
fi

chown -R mysql.mysql /usr/local/$mysql8_version_dir
ln -s /usr/local/$mysql8_version_dir /usr/local/mysql

#./bin/mysqld --defaults-file=/usr/local/mysql/my.cnf --initialize --user=mysql 2>&1 | tee password.txt
#mysql_password=`awk '/A temporary password/{print $NF}' /usr/local/mysql/password.txt`

./bin/mysqld --defaults-file=/usr/local/mysql/my.cnf --initialize --user=mysql	#--lower-case-table-names=1
mysql_password=`awk '/A temporary password/{print $NF}' /data/mysql/log/error.log`

bin/mysql_ssl_rsa_setup --datadir=/data/mysql/data

cat > /usr/lib/systemd/system/mysqld.service << 'EOF'
[Unit]
Description=MySQL Server
After=network.target
After=syslog.target
 
[Service]
User=mysql
Group=mysql
 
Type=notify
 
TimeoutSec=0
 
PermissionsStartOnly=true
 
# 修改这里的 ExecStart 为指定的 my.cnf 文件路径
ExecStart=/usr/local/mysql/bin/mysqld --defaults-file=/usr/local/mysql/my.cnf $MYSQLD_OPTS
 
EnvironmentFile=-/etc/sysconfig/mysql
 
LimitNOFILE = 10000
 
Restart=on-failure
 
RestartPreventExitStatus=1
 
Environment=MYSQLD_PARENT_PID=1
 
PrivateTmp=false
 
[Install]
WantedBy=multi-user.target
EOF
 
systemctl daemon-reload
systemctl enable mysqld
systemctl start mysqld

./bin/mysqladmin -S /usr/local/mysql/mysql.sock -uroot password "$root_passwd" -p$mysql_password

ln -sv /usr/local/mysql/bin/mysql /usr/bin/mysql &> /dev/null
#ln -sv /usr/local/mysql/bin/* /usr/bin/ &> /dev/null

expect &> /dev/null <<EOF
spawn ./bin/mysql_secure_installation -S /usr/local/mysql/mysql.sock
expect {
        "Enter password" { send "$root_passwd\n";exp_continue }
        "Press y" { send "n\n";exp_continue }
        "Change the password" { send "n\n";exp_continue }
        "Remove anonymous users" { send "y\n";exp_continue }
        "Disallow root login" { send "n\n";exp_continue }
        "Remove test database" { send "y\n";exp_continue }
        "Reload privilege" { send "y\n" }
}
EOF

# 创建同步账号
mysql -S /usr/local/mysql/mysql.sock -p$root_passwd -e "set sql_log_bin=0;use mysql; create user '$repl_user'@'%' identified by '$repl_passwd';grant replication slave , replication client on *.* to '$repl_user'@'%';set sql_log_bin=1;"

# 安装clone插件
mysql -S /usr/local/mysql/mysql.sock -p$root_passwd -e "set sql_log_bin=0;INSTALL PLUGIN CLONE SONAME 'mysql_clone.so';create user '$clone_user'@'%' identified by '$clone_passwd';grant BACKUP_ADMIN,CLONE_ADMIN on *.* to '$clone_user'@'%';set sql_log_bin=1;select plugin_name, plugin_status from information_schema.plugins where plugin_name like 'clone';"

# 安装组复制插件
mysql -S /usr/local/mysql/mysql.sock -p$root_passwd -e "set sql_log_bin=0;INSTALL PLUGIN group_replication SONAME 'group_replication.so';set sql_log_bin=1;select plugin_name, plugin_status from information_schema.plugins where plugin_name like 'group_replication';"

mysql -S /usr/local/mysql/mysql.sock -p$root_passwd -e "update mysql.user set host = '%' where user = 'root';flush privileges;select host,user from mysql.user;"

# 清空binlog文件，恢复起始文件mysql-bin.000001和Position位置号157
mysql -S /usr/local/mysql/mysql.sock -p$root_passwd -e "reset master;"

systemctl stop mysqld && systemctl start mysqld

echo "数据库安装成功"
