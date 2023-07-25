/* the excluded cve above with a space at the end does not need to be accounted for, it has a proper companion */
/* There are also the usual malformed duplicate rows caused by that 29 error, but one of them ('CVE-202026558 (Non-') has 2 sets of identical rows. This chooses a particular one.*/

INSERT INTO nvip2.cvss (cve_id, create_date, base_score, impact_score)
SELECT cve_id, NOW(), CAST(cvss_severity_id AS DOUBLE), CAST(impact_score AS DOUBLE) FROM nvip_old.cvssscore 
WHERE cve_id NOT LIKE '% ' and cve_id not like 'CVE-2020-26558 (Non-'
GROUP BY cve_id, cvss_severity_id, impact_score;

INSERT INTO nvip2.cvss (cve_id, create_date, base_score, impact_score)
VALUES ('CVE-2020-26558 (Non-', NOW(), 2.0, 6.449999999999999);