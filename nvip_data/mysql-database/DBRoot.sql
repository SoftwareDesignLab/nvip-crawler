CREATE DATABASE IF NOT EXISTS nvip_new
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;

USE nvip_new;

-- Needed for parallel db processes
SET GLOBAL max_connections = 600;
-- Disable Group By requirement for aggregations
SET GLOBAL sql_mode="STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION";

--
-- Table structure for table `vulnerability`
--

DROP TABLE IF EXISTS `vulnerability`;
CREATE TABLE `vulnerability` (
  `vuln_id` INT NOT NULL AUTO_INCREMENT,
  `cve_id` VARCHAR(20) NOT NULL,
  `description` MEDIUMTEXT NOT NULL,
  `created_date` DATETIME NOT NULL,
  `published_date` DATETIME NOT NULL,
  `last_modified_date` DATETIME DEFAULT NULL,
  `status` TINYTEXT NOT NULL,
  PRIMARY KEY (`vuln_id`),
  UNIQUE KEY `vuln_id_UNIQUE` (`vuln_id`),
  KEY `Vulnerability_Index_CveId` (`cve_id`),
  KEY `status_id_idx` (`status_id`)
) 
ENGINE=InnoDB AUTO_INCREMENT=2157992 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;




