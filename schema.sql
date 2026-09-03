-- ============================================================
-- SentinelX Enterprise SOC Platform - Production MySQL Schema
-- ============================================================

CREATE DATABASE IF NOT EXISTS `sentinelx_db` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `sentinelx_db`;

-- 1. Users Table (RBAC Authentication & Profiles)
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(64) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` ENUM('admin', 'analyst', 'auditor') NOT NULL DEFAULT 'analyst',
    `status` VARCHAR(20) NOT NULL DEFAULT 'Active',
    `force_password_change` TINYINT(1) NOT NULL DEFAULT 0,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_users_role` (`role`),
    INDEX `idx_users_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Alerts Table (Security Telemetry & Detections)
CREATE TABLE IF NOT EXISTS `alerts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `alert_id` VARCHAR(64) NOT NULL UNIQUE,
    `title` VARCHAR(255) NOT NULL,
    `severity` ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    `status` ENUM('Open', 'Investigating', 'Resolved', 'Closed') NOT NULL DEFAULT 'Open',
    `source` VARCHAR(64) DEFAULT 'Wazuh',
    `rule_id` VARCHAR(64) DEFAULT NULL,
    `host` VARCHAR(128) DEFAULT NULL,
    `user` VARCHAR(64) DEFAULT NULL,
    `src_ip` VARCHAR(45) DEFAULT NULL,
    `dst_ip` VARCHAR(45) DEFAULT NULL,
    `details` TEXT DEFAULT NULL,
    `raw_payload` LONGTEXT DEFAULT NULL,
    `timestamp` VARCHAR(64) DEFAULT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_alerts_severity` (`severity`),
    INDEX `idx_alerts_status` (`status`),
    INDEX `idx_alerts_src_ip` (`src_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Cases Table (Incident Management & Workflow)
CREATE TABLE IF NOT EXISTS `cases` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `case_id` VARCHAR(64) NOT NULL UNIQUE,
    `title` VARCHAR(255) NOT NULL,
    `description` TEXT DEFAULT NULL,
    `severity` ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    `status` ENUM('Open', 'In Progress', 'Resolved', 'Closed') NOT NULL DEFAULT 'Open',
    `assigned_to` VARCHAR(64) DEFAULT 'Unassigned',
    `alert_ids` TEXT DEFAULT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_cases_status` (`status`),
    INDEX `idx_cases_assigned` (`assigned_to`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Audit Logs Table (SOC Compliance & Evidence Trail)
CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `timestamp` VARCHAR(64) NOT NULL,
    `username` VARCHAR(64) NOT NULL,
    `action` VARCHAR(128) NOT NULL,
    `details` TEXT DEFAULT NULL,
    `ip` VARCHAR(45) DEFAULT '127.0.0.1',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_audit_user` (`username`),
    INDEX `idx_audit_action` (`action`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Blocked IPs Table (SOAR Network Containment)
CREATE TABLE IF NOT EXISTS `blocked_ips` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ip` VARCHAR(45) NOT NULL UNIQUE,
    `reason` VARCHAR(255) DEFAULT 'Threat Intelligence Match',
    `blocked_by` VARCHAR(64) DEFAULT 'SOAR Playbook',
    `blocked_at` VARCHAR(64) DEFAULT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. Custom Detection Rules Table
CREATE TABLE IF NOT EXISTS `custom_rules` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `rule_id` VARCHAR(64) NOT NULL UNIQUE,
    `rule_name` VARCHAR(255) NOT NULL,
    `severity` VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    `category` VARCHAR(64) DEFAULT 'Endpoint',
    `pattern` TEXT DEFAULT NULL,
    `status` VARCHAR(20) NOT NULL DEFAULT 'Active',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed Default Production Accounts
INSERT INTO `users` (`username`, `password_hash`, `role`, `status`) 
VALUES 
('nani', '$2b$12$mRSzB1Zvhsr7pggU83NwHOhAFTd9iqMFgqs39L/3Vay9l48A6iNJ2', 'admin', 'Active'),
('analyst', '$2b$12$xN2IhNrZTg1PgjbLTXEqGeYn7LV6WXGPs9zRkvtKHz5oMpLHTW2Dq', 'analyst', 'Active')
ON DUPLICATE KEY UPDATE `role`=VALUES(`role`);
