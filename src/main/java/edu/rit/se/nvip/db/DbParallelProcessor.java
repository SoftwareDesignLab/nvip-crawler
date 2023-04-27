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
							count = databaseHelper.updateVulnerability(vuln);

							/**
							 * Update NVD and MITRE status'
							 */
							databaseHelper.updateNvdStatus(vuln.getNvdStatus(), vuln.getCveId());
							databaseHelper.updateMitreStatus(vuln.getMitreStatus(), vuln.getCveId());

							/**
							 * Update Time Gaps
							 */
							databaseHelper.updateNvdTimeGap(vuln.getTimeGapNvd(), vuln.getCveId());
							databaseHelper.updateMitreTimeGap(vuln.getTimeGapMitre(), vuln.getCveId());

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

			int newCveCount = 0;
			for (CompositeVulnerability vuln : vulnList) {
				Vulnerability existingAttribs = existingVulnMap.get(vuln.getCveId());
				if (existingVulnMap.containsKey(vuln.getCveId())) {
					// Update CVE History
					updateCVEHistory(vuln, existingAttribs);
				} else
					newCveCount++;
			}
			logger.info("Done! Checked time gaps for {} (of {}) CVEs! # of new CVEs: {}", existingVulnMap.size(),
					vulnList.size(), newCveCount);

			logger.info("Active, Idle and Total connections AFTER insert (before shutdown): {}", databaseHelper.getConnectionStatus());
			databaseHelper.shutdown();
		}


		/**
		 * For updating a CVEs history if a Vulnerability NVD/MITRE status what updated
		 *
		 * @param vuln
		 * @param existingAttribs
		 */
		public void updateCVEHistory(CompositeVulnerability vuln, Vulnerability existingAttribs) {
			boolean vulnAlreadyInNvd = existingAttribs.doesExistInNvd();
			boolean vulnAlreaadyInMitre = existingAttribs.doesExistInMitre();

			/**
			 * nvd or mitre status change?
			 */
			boolean nvdStatusChanged = (existingAttribs.getNvdStatus() != vuln.getNvdStatus());
			boolean mitreStatusChanged = (existingAttribs.getMitreStatus() != vuln.getMitreStatus());

			if (nvdStatusChanged || mitreStatusChanged) {

				LocalDateTime createdDateTime = null;

				boolean recordTimeGap = (existingAttribs.getCreateDate() != null)
						&& ((!vulnAlreadyInNvd && vuln.doesExistInNvd()) || (!vulnAlreaadyInMitre && vuln.doesExistInMitre()))
						&& !CveUtils.isCveReservedEtc(vuln.getDescription());


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
				 * Record time gaps in history, if any
				 */
				if (recordTimeGap) {
					if (!vulnAlreadyInNvd && vuln.doesExistInNvd()) {
						databaseHelper.addToCveStatusChangeHistory(vuln, existingAttribs, "NVD", existingAttribs.getNvdStatus(),
								vuln.getNvdStatus(), true, vuln.getTimeGapNvd());
					}
					if (!vulnAlreaadyInMitre && vuln.doesExistInMitre()) {
						databaseHelper.addToCveStatusChangeHistory(vuln, existingAttribs, "MITRE", existingAttribs.getMitreStatus(),
								vuln.getMitreStatus(), true, vuln.getTimeGapMitre());
					}
				} else {
					if (nvdStatusChanged)
						databaseHelper.addToCveStatusChangeHistory(vuln, existingAttribs, "NVD", existingAttribs.getNvdStatus(),
								vuln.getNvdStatus(), false, 0);

					if (mitreStatusChanged)
						databaseHelper.addToCveStatusChangeHistory(vuln, existingAttribs, "MITRE", existingAttribs.getMitreStatus(),
								vuln.getMitreStatus(), false, 0);
				}
			}
		}
	}

}
