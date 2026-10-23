SELECT
CASE
  WHEN enrichments[1]['name'] = 'prevalence' AND enrichments[1]['provider'] = 'nano' AND enrichments[1]['data']['artifact_type'] = 'ip_address' THEN enrichments[1]['value']
  WHEN enrichments[2]['name'] = 'prevalence' AND enrichments[2]['provider'] = 'nano' AND enrichments[2]['data']['artifact_type'] = 'ip_address' THEN enrichments[2]['value']
  WHEN enrichments[3]['name'] = 'prevalence' AND enrichments[3]['provider'] = 'nano' AND enrichments[3]['data']['artifact_type'] = 'ip_address' THEN enrichments[3]['value']
  WHEN enrichments[4]['name'] = 'prevalence' AND enrichments[4]['provider'] = 'nano' AND enrichments[4]['data']['artifact_type'] = 'ip_address' THEN enrichments[4]['value']
  WHEN enrichments[5]['name'] = 'prevalence' AND enrichments[5]['provider'] = 'nano' AND enrichments[5]['data']['artifact_type'] = 'ip_address' THEN enrichments[5]['value']
  WHEN enrichments[6]['name'] = 'prevalence' AND enrichments[6]['provider'] = 'nano' AND enrichments[6]['data']['artifact_type'] = 'ip_address' THEN enrichments[6]['value']
END AS artifact,
CASE
  WHEN enrichments[1]['name'] = 'prevalence' AND enrichments[1]['provider'] = 'nano' AND enrichments[1]['data']['artifact_type'] = 'ip_address' THEN enrichments[1]['data']['host_count']
  WHEN enrichments[2]['name'] = 'prevalence' AND enrichments[2]['provider'] = 'nano' AND enrichments[2]['data']['artifact_type'] = 'ip_address' THEN enrichments[2]['data']['host_count']
  WHEN enrichments[3]['name'] = 'prevalence' AND enrichments[3]['provider'] = 'nano' AND enrichments[3]['data']['artifact_type'] = 'ip_address' THEN enrichments[3]['data']['host_count']
  WHEN enrichments[4]['name'] = 'prevalence' AND enrichments[4]['provider'] = 'nano' AND enrichments[4]['data']['artifact_type'] = 'ip_address' THEN enrichments[4]['data']['host_count']
  WHEN enrichments[5]['name'] = 'prevalence' AND enrichments[5]['provider'] = 'nano' AND enrichments[5]['data']['artifact_type'] = 'ip_address' THEN enrichments[5]['data']['host_count']
  WHEN enrichments[6]['name'] = 'prevalence' AND enrichments[6]['provider'] = 'nano' AND enrichments[6]['data']['artifact_type'] = 'ip_address' THEN enrichments[6]['data']['host_count']
END AS hosts,
CASE
  WHEN enrichments[1]['name'] = 'prevalence' AND enrichments[1]['provider'] = 'nano' AND enrichments[1]['data']['artifact_type'] = 'ip_address' THEN enrichments[1]['data']['host_count_saturated']
  WHEN enrichments[2]['name'] = 'prevalence' AND enrichments[2]['provider'] = 'nano' AND enrichments[2]['data']['artifact_type'] = 'ip_address' THEN enrichments[2]['data']['host_count_saturated']
  WHEN enrichments[3]['name'] = 'prevalence' AND enrichments[3]['provider'] = 'nano' AND enrichments[3]['data']['artifact_type'] = 'ip_address' THEN enrichments[3]['data']['host_count_saturated']
  WHEN enrichments[4]['name'] = 'prevalence' AND enrichments[4]['provider'] = 'nano' AND enrichments[4]['data']['artifact_type'] = 'ip_address' THEN enrichments[4]['data']['host_count_saturated']
  WHEN enrichments[5]['name'] = 'prevalence' AND enrichments[5]['provider'] = 'nano' AND enrichments[5]['data']['artifact_type'] = 'ip_address' THEN enrichments[5]['data']['host_count_saturated']
  WHEN enrichments[6]['name'] = 'prevalence' AND enrichments[6]['provider'] = 'nano' AND enrichments[6]['data']['artifact_type'] = 'ip_address' THEN enrichments[6]['data']['host_count_saturated']
END AS common,
count(*) AS events
FROM <namespace>.<table>
WHERE {window}
  AND (CASE
  WHEN enrichments[1]['name'] = 'prevalence' AND enrichments[1]['provider'] = 'nano' AND enrichments[1]['data']['artifact_type'] = 'ip_address' THEN enrichments[1]['data']['host_count']
  WHEN enrichments[2]['name'] = 'prevalence' AND enrichments[2]['provider'] = 'nano' AND enrichments[2]['data']['artifact_type'] = 'ip_address' THEN enrichments[2]['data']['host_count']
  WHEN enrichments[3]['name'] = 'prevalence' AND enrichments[3]['provider'] = 'nano' AND enrichments[3]['data']['artifact_type'] = 'ip_address' THEN enrichments[3]['data']['host_count']
  WHEN enrichments[4]['name'] = 'prevalence' AND enrichments[4]['provider'] = 'nano' AND enrichments[4]['data']['artifact_type'] = 'ip_address' THEN enrichments[4]['data']['host_count']
  WHEN enrichments[5]['name'] = 'prevalence' AND enrichments[5]['provider'] = 'nano' AND enrichments[5]['data']['artifact_type'] = 'ip_address' THEN enrichments[5]['data']['host_count']
  WHEN enrichments[6]['name'] = 'prevalence' AND enrichments[6]['provider'] = 'nano' AND enrichments[6]['data']['artifact_type'] = 'ip_address' THEN enrichments[6]['data']['host_count']
END) BETWEEN 1 AND 2
  AND (CASE
  WHEN enrichments[1]['name'] = 'prevalence' AND enrichments[1]['provider'] = 'nano' AND enrichments[1]['data']['artifact_type'] = 'ip_address' THEN enrichments[1]['data']['host_count_saturated']
  WHEN enrichments[2]['name'] = 'prevalence' AND enrichments[2]['provider'] = 'nano' AND enrichments[2]['data']['artifact_type'] = 'ip_address' THEN enrichments[2]['data']['host_count_saturated']
  WHEN enrichments[3]['name'] = 'prevalence' AND enrichments[3]['provider'] = 'nano' AND enrichments[3]['data']['artifact_type'] = 'ip_address' THEN enrichments[3]['data']['host_count_saturated']
  WHEN enrichments[4]['name'] = 'prevalence' AND enrichments[4]['provider'] = 'nano' AND enrichments[4]['data']['artifact_type'] = 'ip_address' THEN enrichments[4]['data']['host_count_saturated']
  WHEN enrichments[5]['name'] = 'prevalence' AND enrichments[5]['provider'] = 'nano' AND enrichments[5]['data']['artifact_type'] = 'ip_address' THEN enrichments[5]['data']['host_count_saturated']
  WHEN enrichments[6]['name'] = 'prevalence' AND enrichments[6]['provider'] = 'nano' AND enrichments[6]['data']['artifact_type'] = 'ip_address' THEN enrichments[6]['data']['host_count_saturated']
END) = false
GROUP BY 1,2,3
ORDER BY events DESC
LIMIT 10
