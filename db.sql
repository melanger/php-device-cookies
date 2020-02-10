CREATE TABLE IF NOT EXISTS `user_devicecookie_failedattempts` (
  `attempt_id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) NOT NULL COMMENT 'refer to users.id',
  `login` varchar(255) DEFAULT NULL,
  `datetime` datetime DEFAULT current_timestamp() COMMENT 'failed authentication on date/time',
  `devicecookie_nonce` varchar(50) DEFAULT NULL COMMENT 'device cookie NONCE (if present).',
  `devicecookie_signature` longtext DEFAULT NULL COMMENT 'device cookie signature (if present).',
  PRIMARY KEY (`attempt_id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=COMPACT COMMENT='contain login failed attempt for existing users.';

CREATE TABLE IF NOT EXISTS `user_devicecookie_lockout` (
  `lockout_id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) DEFAULT NULL COMMENT 'refer to users.id',
  `devicecookie_nonce` varchar(50) DEFAULT NULL COMMENT 'device cookie NONCE.',
  `devicecookie_signature` longtext DEFAULT NULL COMMENT 'device cookie signature.',
  `lockout_untrusted_clients` int(1) NOT NULL DEFAULT 0 COMMENT '0=just lockout selected device cookie, 1=lockout all untrusted clients.',
  `lockout_until` datetime DEFAULT NULL COMMENT 'lockout selected user (user_id) until date/time.',
  PRIMARY KEY (`lockout_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=COMPACT COMMENT='contain user account lockout.';
