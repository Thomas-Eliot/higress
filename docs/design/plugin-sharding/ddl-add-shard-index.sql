-- 消费者表新增 shard_index 字段
ALTER TABLE higress_consumer ADD COLUMN shard_index INT DEFAULT NULL COMMENT '分片索引（MurmurHash(consumerId) % 64）' AFTER enable;
CREATE INDEX idx_consumer_shard ON higress_consumer (gw_instance_id, shard_index);

-- 授权关系表新增 shard_index 字段
ALTER TABLE higress_authorization ADD COLUMN shard_index INT DEFAULT NULL COMMENT '分片索引（MurmurHash(appId) % 64，跟随 consumer 分片）' AFTER grant_target_id;
CREATE INDEX idx_authorization_shard ON higress_authorization (gw_instance_id, shard_index);

-- credential_key 唯一索引（同实例下不允许重复 key）
CREATE UNIQUE INDEX uk_consumer_credential ON higress_consumer (gw_instance_id, credential_key);

-- 回填已有数据的 shard_index（需要在应用层执行，因为 MurmurHash 在 SQL 中不好实现）
-- 方案：启动时 ConfigMapDataMigrator 会重新 save 所有数据，自动填充 shard_index
