INSERT INTO nvip2.vdocharacteristic (cve_id, created_date, vdo_label, vdo_noun_group, vdo_confidence)
SELECT vc.cve_id, v.created_date, vl.vdo_label_for_ui, vn.vdo_name_for_ui, vc.vdo_confidence
FROM nvip_old.vdocharacteristic AS vc 
INNER JOIN nvip_old.vdolabel AS vl ON vc.vdo_label_id = vl.vdo_label_id
INNER JOIN nvip_old.vdonoungroup AS vn ON vc.vdo_noun_group_id = vn.vdo_noun_group_id
INNER JOIN nvip2.vulnerability AS v ON vc.cve_id = v.cve_id;