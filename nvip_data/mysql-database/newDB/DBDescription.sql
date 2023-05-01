--
-- Table structure for table `description`
--

DROP TABLE IF EXISTS `description`;
CREATE TABLE `description` (
  `description_id` INT NOT NULL AUTO_INCREMENT,
  `cve_id` VARCHAR(20) NOT NULL,
  `description` MEDIUMTEXT NOT NULL,
  `created_date` DATETIME NOT NULL,
  `gpt_func` TINYTEXT NOT NULL,
  PRIMARY KEY (`description_id`),
  KEY `description_index_cve_id` (`cve_id`),
  CONSTRAINT `description_cve_id_fk` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6202 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Table structure for table `rawdescriptionjt`
--

DROP TABLE IF EXISTS `rawdescriptionjt`;
CREATE TABLE `rawdescriptionjt` (
  `description_joint_id` INT NOT NULL AUTO_INCREMENT,
  `description_id` INT NOT NULL,
  `raw_description_id` INT NOT NULL,
  PRIMARY KEY (`description_joint_id`),
  KEY `description_index_joint_id` (`description_joint_id`),
  CONSTRAINT `description_joint_description_id_fk` FOREIGN KEY (`description_id`) REFERENCES `description` (`description_id`),
  CONSTRAINT `description_joint_raw_description_id_fk` FOREIGN KEY (`raw_description_id`) REFERENCES `rawdescription` (`raw_description_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6202 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Table structure for table `description`
--
DROP TABLE IF EXISTS `rawdescription`;
CREATE TABLE `rawdescription` (
  `raw_description_id` INT NOT NULL AUTO_INCREMENT,
  `raw_description` MEDIUMTEXT NOT NULL,
  `created_date` DATETIME NOT NULL,
  `source_url` TINYTEXT NOT NULL,
  PRIMARY KEY (`raw_description_id`),
  KEY `raw_description_index_id` (`raw_description_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6202 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
