--
-- Table structure for table `cvssscore`
--

DROP TABLE IF EXISTS `cvssscore`;
CREATE TABLE `cvssscore` (
  `cve_id` VARCHAR(20) NOT NULL,
  `create_date` DATETIME NOT NULL,
  `base_score` DOUBLE NOT NULL,
  `impact_score` DOUBLE NOT NULL,
  KEY `cvss_cve_id_index` (`cve_id`),
  CONSTRAINT `cvssscore_cve_id_fk` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;