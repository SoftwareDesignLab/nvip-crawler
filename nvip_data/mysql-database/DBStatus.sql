--
-- Table structure for table `nvdmitrestatus`
--

DROP TABLE IF EXISTS nvdmitrestatus;
CREATE TABLE `nvdmitrestatus` (
    `nvdmitrestatus_id` INT NOT NULL AUTO_INCREMENT,
    `cve_id` VARCHAR(20) NOT NULL,
    `created_date` DATETIME NOT NULL,
    `status_nvd` TINYTEXT NOT NULL,
    `status_mitre` TINYTEXT NOT NULL,
    PRIMARY KEY (`nvdmitrestatus_id`),
	KEY `Nvdmitrestatus_Index_CveId` (`cve_id`),
	CONSTRAINT `nvdmitrestatus_cve_id_fk` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;