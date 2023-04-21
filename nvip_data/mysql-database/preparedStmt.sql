INSERT INTO vulnerabilityaggregate(
	SELECT v.vuln_id,
		   v.cve_id,
		   v.description,
		   v.platform,
		   v.published_date,
		   v.last_modified_date,
		   v.fixed_date,
		   v.exists_at_nvd,
		   v.exists_at_mitre,
		   vc.vdo_labels,
		   vc.vdo_label_confidences,
		   vc.vdo_noun_groups,
		   vsu.urls,
		   cs.base_severities,
		   cs.severity_confidences,
		   cs.impact_scores,
		   cs.impact_confidences,
		   vap.product_id,
		   vap.cpe,
		   vap.domain,
		   vap.version,
		   expl.publish_date,
		   expl.publisher_url,
		   vu.run_date_time
	FROM (SELECT vu.vuln_id,
				 MAX(drh.run_id)        AS "run_id",
				 MAX(drh.run_date_time) AS "run_date_time"
		  FROM dailyrunhistory drh
				   INNER JOIN vulnerabilityupdate vu ON vu.run_id = drh.run_id
		  WHERE drh.run_date_time BETWEEN '2023-04-21 00:00:00' AND '2023-04-22 00:00:00'
		  GROUP BY vu.vuln_id) vu
			 INNER JOIN vulnerability v
						ON v.vuln_id = vu.vuln_id
			 LEFT JOIN (SELECT vc.cve_id,
							   group_concat(DISTINCT vl.vdo_label_name SEPARATOR ';') AS vdo_labels,
							   group_concat(DISTINCT vc.vdo_confidence SEPARATOR ';') AS vdo_label_confidences,
							   group_concat(DISTINCT ifnull(vn.vdo_noun_group_name, 'None')
											SEPARATOR
											';')                                      AS vdo_noun_groups
						FROM vdocharacteristic vc
								 INNER JOIN vdonoungroup vn ON vn.vdo_noun_group_id = vc.vdo_noun_group_id
								 INNER JOIN vdolabel vl ON vl.vdo_label_id = vc.vdo_label_id
						GROUP BY vc.cve_id) vc
					   ON vc.cve_id = v.cve_id
			 LEFT JOIN (SELECT cve_id,
							   group_concat(DISTINCT url SEPARATOR ';') AS urls
						FROM vulnsourceurl
						GROUP BY cve_id) vsu
					   ON vsu.cve_id = v.cve_id
			 LEFT JOIN (SELECT csc.cve_id,
							   group_concat(DISTINCT cse.cvss_severity_class SEPARATOR ';') AS base_severities,
							   group_concat(DISTINCT csc.severity_confidence SEPARATOR ';') AS severity_confidences,
							   group_concat(DISTINCT csc.impact_score SEPARATOR ';')        AS impact_scores,
							   group_concat(DISTINCT csc.impact_confidence SEPARATOR ';')   AS impact_confidences
						FROM cvssscore csc
								 INNER JOIN cvssseverity cse ON cse.cvss_severity_id = csc.cvss_severity_id
						GROUP BY csc.cve_id) cs
					   ON cs.cve_id = v.cve_id
			 LEFT JOIN (SELECT cve_id,
							   group_concat(DISTINCT ar.product_id SEPARATOR ';') AS product_id,
							   group_concat(DISTINCT cpe SEPARATOR ';')           AS cpe,
							   group_concat(DISTINCT domain SEPARATOR ';')        AS domain,
							   group_concat(DISTINCT version SEPARATOR ';')       AS version
						FROM affectedrelease ar
								 INNER JOIN product p ON p.product_id = ar.product_id
						GROUP BY cve_id) vap
					   ON vap.cve_id = v.cve_id
			 LEFT JOIN exploit as expl on expl.vuln_id = v.vuln_id
	WHERE v.status_id <> 2
	  and v.description is not null
	  and v.description not like '%** RESERVED ** This candidate%'
	  and v.description not like '%** REJECT ** DO NOT USE%'
	  and length(v.description) >= 50
	  and vdo_labels is not null
	ORDER BY v.vuln_id desc
);
SELECT count(*) INTO cveCount FROM vulnerabilityaggregate;