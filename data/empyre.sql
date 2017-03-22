DROP TABLE IF EXISTS `agents`;
CREATE TABLE `agents` (
    `id` integer PRIMARY KEY,
    `session_id` text,
    `listener` text,
    `name` text,
    `delay` integer,
    `jitter` real,
    `external_ip` text,
    `internal_ip` text,
    `username` text,
    `high_integrity` integer,
    `process_id` text,
    `hostname` text,
    `os_details` text,
    `session_key` text,
    `nonce` text,
    `checkin_time` text,
    `lastseen_time` text,
    `servers` text,
    `uris` text,
    `old_uris` text,
    `user_agent` text,
    `headers` text,
    `kill_date` text,
    `working_hours` text,
    `py_version` text,
    `lost_limit` integer,
    `taskings` text,
    `results` text
    );
DROP TABLE IF EXISTS `config`;
CREATE TABLE config (
    `staging_key` text,
    `stage0_uri` text,
    `stage1_uri` text,
    `stage2_uri` text,
    `default_delay` integer,
    `default_jitter` real,
    `default_profile` text,
    `default_cert_path` text,
    `default_port` text,
    `install_path` text,
    `server_version` text,
    `ip_whitelist` text,
    `ip_blacklist` text,
    `default_lost_limit` integer,
    `autorun_command` text,
    `autorun_data` text,
    `rootuser` boolean,
    `api_username` text,
    `api_password` text,
    `api_current_token` text,
    `api_permanent_token` text
    );
INSERT INTO `config` VALUES('FM+T6EJbRk}_~Q2j*VPhg7I#BC=4mYW$','index.asp','index.jsp','index.php',5,0,'/admin/get.php,/news.asp,/login/process.jsp|Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:45.0) Gecko/20100101 Firefox/45.0','','8080','/home/l33t/Documents/FromA2Z/EmPyre/','Microsoft-IIS/7.5','','',60,'','',0,'empyreadmin','etI_H`}!7Dl@u.~C59&rb-vPOy6Mq3s8','','up0mplrvih978cy2nuz8255ufhptrgch1sconx2n');
DROP TABLE IF EXISTS `credentials`;
CREATE TABLE `credentials` (
    `id` integer PRIMARY KEY,
    `credtype` text,
    `domain` text,
    `username` text,
    `password` text,
    `host` text,
    `sid` text,
    `notes` text
    );
DROP TABLE IF EXISTS `listeners`;
CREATE TABLE `listeners` (
    `id` integer PRIMARY KEY,
    `name` text,
    `host` text,
    `port` integer,
    `cert_path` text,
    `staging_key` text,
    `default_delay` integer,
    `default_jitter` real,
    `default_profile` text,
    `kill_date` text,
    `working_hours` text,
    `listener_type` text,
    `redirect_target` text,
    `default_lost_limit` integer
    );
DROP TABLE IF EXISTS `reporting`;
CREATE TABLE `reporting` (
    `id` integer PRIMARY KEY,
    `name` text,
    `event_type` text,
    `message` text,
    `time_stamp` text
    );
