/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import edu.rit.se.nvip.model.Vulnerability;
import org.apache.commons.collections4.ListUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.model.CompositeVulnerability;

/**
 * 
 * 
 * Store CVEs with multi-threading
 * 
 * @author axoeec
 *
 */
public class DbParallelProcessor {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public DbParallelProcessor() {

	}

	/**
	 * Generate a thread pool and run in parallel
	 * 
	 * @param vulnList
	 * @return
	 */
	public boolean executeInParallel(List<CompositeVulnerability> vulnList, int runId) {
		boolean done = false;
		long start = System.currentTimeMillis();

		int numOfRecordsPerThread = 25000;
		List<List<CompositeVulnerability>> vulnList2 = ListUtils.partition(vulnList, numOfRecordsPerThread);

		int numberOfThreads = vulnList.size() / numOfRecordsPerThread + 1;
		logger.info("Spawning {} threads to record {} CVEs", numOfRecordsPerThread, vulnList.size());
		ExecutorService pool = Executors.newFixedThreadPool(numberOfThreads);

		/**
		 * TODO: As our CVE sources grow, there's starting to be a limit on how many threads we use.
		 * TODO: Should try and limit this to work with larger data.
		 */

		int i = 0;

		for (List<CompositeVulnerability> subList : vulnList2) {
			if (i < 9) {
				Runnable runnable = new VulnRecordThread(subList, runId);
				pool.execute(runnable);
			}
			i++;
		}

		// shut down pool
		try {
			pool.shutdown();
			done = pool.awaitTermination(180, TimeUnit.MINUTES);
			long end = System.currentTimeMillis();
			logger.info(getClass().getSimpleName() + " time for " + vulnList.size() + " items: " + ((end - start)) + " mseconds!");
			if (!done) {
				logger.error("A serious error has occurred! The parallel job was terminated due to timeout before DONE! Check log files!");
			}

			DatabaseHelper.clearExistingVulnMap(); // clear existing CVEs map!
		} catch (InterruptedException e2) {
			logger.error(
					"Error while awaiting task completion! # of threads: " + numberOfThreads + " # of lists in the partitioned large vuln list: " + vulnList2.size() + " Exception: " + e2.toString());
		}

		return done;
	}

	/**
	 * Store (insert or update) a set of CVEs.
	 * 
	 * @author Ahmet Okutan
	 *
	 */
	private class VulnRecordThread extends Thread implements Runnable {
		DatabaseHelper databaseHelper;
		private final List<CompositeVulnerability> vulnList;
		private int runId = 0;

		public VulnRecordThread(List<CompositeVulnerability> vulnList, int runId) {
			logger.info("NEW VULN RECORD THREAD");
			this.vulnList = vulnList;
			this.runId = runId;
			databaseHelper = DatabaseHelper.getInstanceForMultiThreading();
		}

		// run process
		public void run() {
			logger.info("Active, Idle and Total connections BEFORE insert: {}", databaseHelper.getConnectionStatus());
			Map<String, Vulnerability> existingVulnMap = databaseHelper.getExistingVulnerabilities();

			int insertCount = 0, updateCount = 0, noChangeCount = 0;
			for (int i = 0; i < vulnList.size(); i++) {
				CompositeVulnerability vuln = vulnList.get(i);

				if (i % 500 == 0 && i > 0)
					logger.info("Updated/inserted/notchanged {}/{}/{} of {} vulnerabilities", updateCount, insertCount,
							noChangeCount, vulnList.size());

				try {
					if (existingVulnMap.containsKey(vuln.getCveId())) {
						int count = databaseHelper.updateVulnerability(vuln, existingVulnMap, runId);
						if (count > 0)
							updateCount++;
						else
							noChangeCount++;
					} else {
						databaseHelper.insertVulnerability(vuln);

						/**
						 * insert sources
						 */
						insertVulnSource(vuln.getVulnSourceList(), connection);

						/**
						 * insert VDO
						 */
						insertVdoCharacteristic(vuln.getVdoCharacteristicInfo(), connection);

						/**
						 * insert CVSS
						 */
						insertCvssScore(vuln.getCvssScoreInfo(), connection);

						/**
						 * record updates
						 */
						List<Integer> vulnIdList = getVulnerabilityIdList(vuln.getCveId(), connection);
						for (Integer vulnId : vulnIdList)
							insertVulnerabilityUpdate(vulnId, "description", "New CVE: " + vuln.getCveId(), runId, connection);

						insertCount++;
					}
				} catch (Exception e) {
					logger.error("ERROR: Failed to insert CVE: {}\n{}", vuln.getCveId(), e.toString());
				}

			}

			int total = updateCount + insertCount + noChangeCount;
			logger.info("DatabaseHelper updated/inserted/notchanged {} [ {}/{}/{} ] of {} vulnerabilities.",
					total, updateCount, insertCount, noChangeCount, vulnList.size());

			// do time gap analysis for CVEs in vulnList
			checkNvdMitreStatusForCrawledVulnerabilityList(connection, vulnList, existingVulnMap);


			databaseHelper.recordVulnerabilityList(vulnList, runId);
			logger.info("Active, Idle and Total connections AFTER insert (before shutdown): {}", databaseHelper.getConnectionStatus());
			databaseHelper.shutdown();
		}
	}

}
