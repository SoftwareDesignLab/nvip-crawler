USE nvip2;

DROP FUNCTION IF EXISTS get_chunk;
DROP FUNCTION IF EXISTS handle_dash;
DROP FUNCTION IF EXISTS handle_space;

/* cpes are a bunch of substrings joined by a colon. this gets a particular substring */
DELIMITER //
CREATE FUNCTION get_chunk(cpe VARCHAR(300), chunk INT)
RETURNS TINYTEXT
DETERMINISTIC
BEGIN
    IF cpe IS NULL OR chunk <= 0 THEN 
        RETURN NULL; 
    END IF;

    SET @start_pos := 1;
    SET @delimiter_count := 0;

    WHILE @start_pos > 0 AND @delimiter_count < chunk DO
        SET @delimiter_count := @delimiter_count + 1;
        SET @start_pos := LOCATE(':', cpe, @start_pos + 1);
    END WHILE;

    IF @start_pos = 0 THEN
        RETURN NULL;
    END IF;

    IF @delimiter_count = chunk THEN
        SET @end_pos := LOCATE(':', cpe, @start_pos + 1);
        IF @end_pos = 0 THEN
            RETURN SUBSTRING(cpe, @start_pos + 1);
        ELSE
            RETURN SUBSTRING(cpe, @start_pos + 1, @end_pos - @start_pos - 1);
        END IF;
    ELSE
        RETURN NULL;
    END IF;
END//

CREATE FUNCTION handle_dash(version TINYTEXT)
RETURNS TINYTEXT
DETERMINISTIC
BEGIN
	IF version = '-' THEN
		RETURN '*';
	END IF;
	RETURN version;
END//

CREATE FUNCTION handle_space(cve_id TINYTEXT)
RETURNS TINYTEXT
DETERMINISTIC
BEGIN
	IF cve_id = 'CVE-2020-12713 ' THEN
		RETURN 'CVE-2020-12713';
	END IF;
    RETURN cve_id;
END//

DELIMITER ;

/* populates affectedproduct table, uses version in cpe string instead of the version column from the old product table */
/*INSERT INTO nvip2.affectedproduct (cve_id, cpe, product_name, version, vendor, purl, swid_tag)*/
/*SELECT handle_space(a.cve_id), p.cpe, get_chunk(p.cpe, 4), handle_dash(get_chunk(p.cpe, 5)), get_chunk(p.cpe, 3), "", ""*/
SELECT COUNT(*)
FROM nvip_old.affectedrelease AS a
INNER JOIN nvip_old.product AS p ON a.product_id = p.product_id;

DROP FUNCTION get_chunk;
DROP FUNCTION handle_dash;
DROP FUNCTION handle_space;