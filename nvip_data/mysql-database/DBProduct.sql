--
-- Table structure for table `affectedproduct`
--

DROP TABLE IF EXISTS `affectedproduct`;
CREATE TABLE `affectedproduct` (
  `affected_product_id` INT NOT NULL AUTO_INCREMENT,
  `cve_id` VARCHAR(20) NOT NULL,
  `cpe` VARCHAR(300) NOT NULL,
  `release_date` DATETIME NOT NULL,
  `product_name` TINYTEXT NOT NULL,
  `version` TINYTEXT DEFAULT NULL,
  `vendor` TINYTEXT DEFAULT NULL,
  PRIMARY KEY (`affected_product_id`),
  KEY `AffectedProduct_Index_CveId` (`cve_id`),
  CONSTRAINT `affectedproduct_cve_id_fk` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6202 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
