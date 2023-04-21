--
-- Table structure for table `patchsourceurl`
--

DROP TABLE IF EXISTS patchsourceurl;
CREATE TABLE `patchsourceurl` (
    `source_url_id` int NOT NULL AUTO_INCREMENT,
    `source_url` varchar(500) NOT NULL,
    `cve_id` varchar(20) NOT NULL,
    PRIMARY KEY (`source_url_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Table structure for table `patchcommit`
--

DROP TABLE IF EXISTS patchcommit;
CREATE TABLE `patchcommit` (
    `commit_id` INT NOT NULL,
    `commit_url` TINYTEXT NOT NULL,
    `commit_date` DATETIME NOT NULL,
    `commit_message` VARCHAR(500) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;