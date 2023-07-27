INSERT INTO nvip2.runhistory (run_start_date, run_end_date)
SELECT (run_date_time, DATE_ADD(run_date_time, INTERVAL crawl_time_min MINUTE)) FROM nvip.dailyrunhistory