--
-- Table structure for table `vulnerabilityaggregate`
-- Used as a cache table for the Web App
--

DROP TABLE IF EXISTS `vulnerabilityaggregate`;
CREATE TABLE `vulnerabilityaggregate` (
  `vuln_id` int NOT NULL,
  `cve_id` varchar(20) NOT NULL,
  `description` mediumtext NOT NULL,
  `published_date` datetime NOT NULL,
  `last_modified_date` datetime DEFAULT NULL,
  `fixed_date` datetime DEFAULT NULL,
  `exists_at_nvd` TINYTEXT NOT NULL,
  `exists_at_mitre` TINYTEXT NOT NULL,
  `vdo_labels` TINYTEXT NOT NULL,
  `vdo_label_confidences` TINYTEXT NOT NULL,
  `vdo_noun_groups` TINYTEXT NOT NULL,
  `source_urls` MEDIUMTEXT NOT NULL,
  `base_scores` TINYTEXT NOT NULL,
  `impact_scores` TINYTEXT NOT NULL,
  `cpes` TINYTEXT NOT NULL,
  `exploit_publish_date` DATETIME DEFAULT NULL,
  `exploit_url` TINYTEXT DEFAULT NULL,
  `runhistory_id` INT NOT NULL,
  KEY `aggregate_cve_id` (`cve_id`),
  KEY `aggregate_run_date_time_id` (`runhistory_id`),
  CONSTRAINT `aggregate_cve_id` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`),
  CONSTRAINT `aggregate_run_date_time_id` FOREIGN KEY (`runhistory_id`) REFERENCES `runhistory` (`runhistory_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
