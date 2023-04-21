--
-- Table structure for table `vdocharacteristic`
--

DROP TABLE IF EXISTS `vdocharacteristic`;
CREATE TABLE `vdocharacteristic` (
  `cve_id` VARCHAR(20) NOT NULL,
  `vdo_label` VARCHAR(30) NOT NULL,
  `vdo_noun_group` VARCHAR(30) NOT NULL,
  `vdo_confidence` DOUBLE NOT NULL,
  KEY `CveId` (`cve_id`),
  CONSTRAINT `vdocharacteristic_cve_id_fk` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;