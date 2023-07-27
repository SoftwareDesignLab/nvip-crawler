/* old db didn't have anything in these tables?? */

INSERT INTO nvip2.patchcommit (source_url_id, commit_url, commit_date, commit_message)
SELECT pc.source_id, pc.commit_url, pc.commit_date,pc.commit_message FROM nvip_old.patchcommit AS pc;

INSERT INTO nvip2.patchsourceurl (source_url_id, cve_id, source_url)
SELECT psu.source_url_id, v.cve_id, psu.source_url FROM nvip_old.patchsourceurl AS psu INNER JOIN nvip_old.vulnerability AS v ON psu.vuln_id = v.vuln_id;