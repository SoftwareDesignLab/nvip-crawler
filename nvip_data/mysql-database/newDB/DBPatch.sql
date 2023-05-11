--
-- Table structure for table `patchsourceurl`
--

DROP TABLE IF EXISTS patchsourceurl;
CREATE TABLE `patchsourceurl` (
    `source_url_id` INT NOT NULL AUTO_INCREMENT,
    `source_url` varchar(500) NOT NULL,
    `cve_id` varchar(20) NOT NULL,
    PRIMARY KEY (`source_url_id`),
    KEY `source_url_id_index` (`source_url_id`),
    CONSTRAINT `patch_source_cve_id_fk` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Table structure for table `patchcommit`
--

DROP TABLE IF EXISTS patchcommit;
CREATE TABLE `patchcommit` (
    `commit_id` INT NOT NULL AUTO_INCREMENT,
    `source_url_id` INT NOT NULL,
    `commit_url` TINYTEXT NOT NULL,
    `commit_date` DATETIME NOT NULL,
    `commit_message` VARCHAR(500) NOT NULL,
    PRIMARY KEY (`commit_id`),
    KEY `commit_id_index` (`commit_id`),
    CONSTRAINT `source_url_id_fk` FOREIGN KEY (`source_url_id`) REFERENCES `patchsourceurl` (`source_url_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;