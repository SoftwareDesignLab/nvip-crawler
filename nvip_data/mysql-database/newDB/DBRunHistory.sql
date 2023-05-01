--
-- Table structure for table `runhistory`
--

DROP TABLE IF EXISTS runhistory;
CREATE TABLE `runhistory` (
    `runhistory_id` INT NOT NULL AUTO_INCREMENT,
    `run_start_date` DATETIME NOT NULL,
    `run_end_date` DATETIME NOT NULL,
    PRIMARY KEY (`runhistory_id`),
    KEY `runhistory_id_idx` (`runhistory_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;