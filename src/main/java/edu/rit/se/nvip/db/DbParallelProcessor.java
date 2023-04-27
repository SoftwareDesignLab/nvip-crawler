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

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import edu.rit.se.nvip.model.Vulnerability;
import edu.rit.se.nvip.utils.CveUtils;
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

			/**
			 * Takes in a list of vulnerabilities (vulnList) and inserts each into the
			 * Vulnerability table in the database. If the CveId exists in the Vulnerability
			 * table already, then the updateVuln function is called.
			 *
			 */
			int insertCount = 0, updateCount = 0, noChangeCount = 0;
			for (int i = 0; i < vulnList.size(); i++) {
				CompositeVulnerability vuln = vulnList.get(i);

				if (i % 500 == 0 && i > 0)
					logger.info("Updated/inserted/notchanged {}/{}/{} of {} vulnerabilities", updateCount, insertCount,
							noChangeCount, vulnList.size());

				try {
					if (existingVulnMap.containsKey(vuln.getCveId())) {
						// check reconcile status, is an update needed?
						// if no need to update then return
						int count;
						Vulnerability existingAttribs = existingVulnMap.get(vuln.getCveId());
						if (vuln.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE) {
							count = 0;
						} else {
							count = databaseHelper.updateVulnerability(vuln, existingVulnMap, runId);
							/**
							 * update sources
							 */
							databaseHelper.deleteVulnSource(vuln.getCveId()); // clear existing ones
							databaseHelper.insertVulnSource(vuln.getVulnSourceList()); // add them

							/**
							 * update vdo
							 */
							databaseHelper.updateVdoLabels(vuln.getCveId(), vuln.getVdoCharacteristicInfo());

							/**
							 * update cvss scores
							 */
							databaseHelper.deleteCvssScore(vuln.getCveId()); // clear existing ones
							databaseHelper.insertCvssScore(vuln.getCvssScoreInfo()); // add them

							/**
							 * record updates if there is an existing vuln
							 */
							if (existingAttribs != null)
								databaseHelper.insertVulnerabilityUpdate(existingAttribs.getVulnID(), "description",
										existingAttribs.getDescription(), runId);
						}

						if (count > 0)
							updateCount++;
						else
							noChangeCount++;
					} else {
						databaseHelper.insertVulnerability(vuln);

						/**
						 * insert sources
						 */
						databaseHelper.insertVulnSource(vuln.getVulnSourceList());

						/**
						 * insert VDO
						 */
						databaseHelper.insertVdoCharacteristic(vuln.getVdoCharacteristicInfo());

						/**
						 * insert CVSS
						 */
						databaseHelper.insertCvssScore(vuln.getCvssScoreInfo());

						/**
						 * record updates
						 */
						List<Integer> vulnIdList = databaseHelper.getVulnerabilityIdList(vuln.getCveId());
						for (Integer vulnId : vulnIdList)
							databaseHelper.insertVulnerabilityUpdate(vulnId, "description", "New CVE: " + vuln.getCveId(), runId);

						insertCount++;
					}
				} catch (Exception e) {
					logger.error("ERROR: Failed to insert CVE: {}\n{}", vuln.getCveId(), e.toString());
				}

			}

			int total = updateCount + insertCount + noChangeCount;
			logger.info("DatabaseHelper updated/inserted/notchanged {} [ {}/{}/{} ] of {} vulnerabilities.",
					total, updateCount, insertCount, noChangeCount, vulnList.size());

			int existingCveCount = 0, newCveCount = 0, timeGapCount = 0;
			try {
				logger.info("Checking time gaps for {} CVEs! # of total CVEs in DB: {}",
						vulnList.size(), existingVulnMap.size());

				for (CompositeVulnerability vuln : vulnList) {
					try {
						if (existingVulnMap.containsKey(vuln.getCveId())) {
							Vulnerability existingAttribs = existingVulnMap.get(vuln.getCveId());
							// check time gap for vuln
							if (checkNvdMitreStatusForVulnerability(vuln, existingAttribs))
								timeGapCount++;
							existingCveCount++;
						} else
							newCveCount++;
					} catch (Exception e) {
						logger.error("Error while checking the time gap for CVE: {}. Err: {} ", vuln.toString(), e.toString());
					}
				}
				logger.info("Done! Checked time gaps for {} (of {}) CVEs! # of new CVEs: {}", existingCveCount,
						vulnList.size(), newCveCount);
			} catch (Exception e) {
				logger.error("Error while checking time gaps for {} CVEs. ", vulnList.size(), e.toString());
			}

			// do time gap analysis for CVEs in vulnList
			//databaseHelper.checkNvdMitreStatusForCrawledVulnerabilityList(vulnList, existingVulnMap);


			logger.info("Active, Idle and Total connections AFTER insert (before shutdown): {}", databaseHelper.getConnectionStatus());
			databaseHelper.shutdown();
		}


		/**
		 * This method calculates the time gaps of a CVE for NVD and MITRE if any. A
		 * time gap for NVD/MITRE is defined as the number of hours between the time a
		 * vulnerability is found by NVIP and the time it is added to NVD/MITRE. Note
		 * that the time gaps calculated here will not be precise, because they will be
		 * depending on the time that NVIP is run. However, they will give an idea about
		 * the value provided by NVIP in terms of EARLY detection of vulnerabilities.
		 *
		 * To calculate a time gap certain conditions must be met:
		 *
		 * (1) CVE has a created date in the database: existingAttribs.getCreatedDate()
		 * != null (We must know when the CVE was first added to db, to calculate a time
		 * gap)
		 *
		 * (2) ((!vulnAlreadyInNvd && vuln.existInNvd()) || (!vulnAlreaadyInMitre &&
		 * vuln.existInMitre())): The CVE did not exist in nvd/mitre before, but it is
		 * there now!
		 *
		 * (3) !CveUtils.isCveReservedEtc(vuln): The new CVE must NOT be
		 * reserved/rejected etc.
		 *
		 * @param vuln
		 * @param existingAttribs
		 */
		public boolean checkNvdMitreStatusForVulnerability(CompositeVulnerability vuln, Vulnerability existingAttribs) {
			boolean timeGapFound = false;
			boolean vulnAlreadyInNvd = existingAttribs.doesExistInNvd();
			boolean vulnAlreaadyInMitre = existingAttribs.doesExistInMitre();

			/**
			 * nvd or mitre status change?
			 */
			boolean nvdStatusChanged = (existingAttribs.getNvdStatus() != vuln.getNvdStatus());
			boolean mitreStatusChanged = (existingAttribs.getMitreStatus() != vuln.getMitreStatus());

			if (nvdStatusChanged || mitreStatusChanged) {

				LocalDateTime createdDateTime = null;
				LocalDateTime lastModifiedDateTime = null;
				try {
					boolean recordTimeGap = (existingAttribs.getCreateDate() != null)
							&& ((!vulnAlreadyInNvd && vuln.doesExistInNvd()) || (!vulnAlreaadyInMitre && vuln.doesExistInMitre()))
							&& !CveUtils.isCveReservedEtc(vuln.getDescription());

					/**
					 * We are not expecting a time gap more than 1 year. If CVE is from prior years
					 * skip time gap check
					 */
					String[] cveParts = vuln.getCveId().split("-");

					if (cveParts.length <= 1) {
						return false;
					}

					int cveYear = Integer.parseInt(cveParts[1]);
					int currentYear = LocalDateTime.now().getYear();
					boolean isCurrentYear = (cveYear == currentYear);
					if (!isCurrentYear)
						recordTimeGap = false;

					if (existingAttribs.getCreateDate() == null || existingAttribs.getCreateDate().toString().isEmpty()) {
						recordTimeGap = false;
					} else {
						createdDateTime = existingAttribs.getCreateDate();
					}

					try {
						lastModifiedDateTime = existingAttribs.getLastModifiedDate();
					} catch (Exception e) {
						logger.warn("WARNING: Could not parse last modified date of Cve: {}, Err: {}\nCve data: {}",
								vuln.getLastModifiedDate(), e.toString(), vuln.toString());
						recordTimeGap = false;
					}

					/**
					 * Record status changes.
					 */
					if (nvdStatusChanged) {
						databaseHelper.updateNvdStatus(vuln.getNvdStatus(), vuln.getCveId());
						logger.info("Changed NVD status of CVE {} from {} to {}", vuln.getCveId(), existingAttribs.getNvdStatus(),
								vuln.getNvdStatus());
					}

					if (mitreStatusChanged) {
						databaseHelper.updateMitreStatus(vuln.getMitreStatus(), vuln.getCveId());
						logger.info("Changed MITRE status of CVE {} from {} to {}", vuln.getCveId(), existingAttribs.getMitreStatus(),
								vuln.getMitreStatus());
					}

					/**
					 * record time gaps if any. We calculate a time gap only if the status changes
					 * from "not-exists" to "exists". Not all status changes require a time gap
					 * calculation. If the CVE was reserved etc. in Mitre, but NVIP has found a
					 * description for it (or did not exist there), we mark its status as-1 (or 0),
					 * to be able to calculate a time gap for it (later on) when it is included in
					 * Mitre with a proper description (not reserved etc.)!
					 */
					int hours;
					if (recordTimeGap) {
						hours = (int) ChronoUnit.HOURS.between(createdDateTime, vuln.getCreateDate());
						if (!vulnAlreadyInNvd && vuln.doesExistInNvd()) {
							// if it did not exist in NVD, but found now, record time gap!
							vuln.setTimeGapNvd(hours);
							databaseHelper.updateNvdTimeGap(vuln.getTimeGapNvd(), vuln.getCveId());
							logger.info("CVE added to NVD! There is {} hours gap!\tCve data: {}", hours, vuln.toString());
							timeGapFound = true;

							// record time gap
							databaseHelper.addToCveStatusChangeHistory(vuln, existingAttribs, "NVD", existingAttribs.getNvdStatus(),
									vuln.getNvdStatus(), true, hours);
						}
						if (!vulnAlreaadyInMitre && vuln.doesExistInMitre()) {
							// if it did not exist in MITRE, but found now, record time gap!
							vuln.setTimeGapMitre(hours);
							databaseHelper.updateMitreTimeGap(vuln.getTimeGapMitre(), vuln.getCveId());
							logger.info("CVE added to MITRE! There is {} hours gap!\tCve data: {}", hours, vuln.toString());
							timeGapFound = true;

							// record time gap
							databaseHelper.addToCveStatusChangeHistory(vuln, existingAttribs, "MITRE", existingAttribs.getMitreStatus(),
									vuln.getMitreStatus(), true, hours);
						}
					} else {
						// just a status change without a time-gap record
						if (nvdStatusChanged)
							databaseHelper.addToCveStatusChangeHistory(vuln, existingAttribs, "NVD", existingAttribs.getNvdStatus(),
									vuln.getNvdStatus(), false, 0);

						if (mitreStatusChanged)
							databaseHelper.addToCveStatusChangeHistory(vuln, existingAttribs, "MITRE", existingAttribs.getMitreStatus(),
									vuln.getMitreStatus(), false, 0);
					}

					return timeGapFound;

				} catch (Exception e) {
					logger.error("Error in checkTimeGaps() {}! Cve record time {}", e.toString(), createdDateTime);
				}

			}

			return false;
		}
	}

}
