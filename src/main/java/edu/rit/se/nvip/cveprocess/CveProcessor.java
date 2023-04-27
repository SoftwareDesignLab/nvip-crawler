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
package edu.rit.se.nvip.cveprocess;

import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.Vulnerability;
import org.apache.commons.collections4.SetUtils;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.cvereconcile.CveReconciler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.CsvUtils;
import org.jdom2.CDATA;

/**
 *
 * Process CVEs to identify the ones not in NVD and MITRE
 *
 * @author axoeec
 *
 */
public class CveProcessor {
	public static final String ALL_CVE_KEY = "all";
	public static final String NVD_CVE_KEY = "nvd";
	public static final String MITRE_CVE_KEY = "mitre";
	public static final String NVD_MITRE_CVE_KEY = "nvd-mitre";

	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	private Map<String, String> cvesInNvd = new HashMap<>();
	private Map<String, String> cvesInMitre = new HashMap<>();

	CveReconciler cveUtils = new CveReconciler();

	public CveProcessor(HashMap<String, String> nvdCves, HashMap<String, String> mitreCves){
		this.cvesInNvd = nvdCves;
		this.cvesInMitre = mitreCves;
	}

	public CveProcessor(String nvdCvePath, String mitreCvePath) {
		try {

			CsvUtils csvLogger = new CsvUtils();
			/**
			 * NVD
			 */
			List<String> arrNVD = FileUtils.readLines(new File(nvdCvePath), "UTF-8");
			if (arrNVD.isEmpty())
				throw new IOException("Failed to read NVD CSV file: " + nvdCvePath + "  ... Calculations of 'not in NVD' are going to be off");
			else
				logger.info("Successfully read in NVD CSV file for calculations of 'not in NVD'");
			for (String cve : arrNVD) {
				String[] pieces = cve.split(csvLogger.getSeparatorCharAsRegex());
				String id = pieces[0];
				if (pieces.length > 2) {
					cvesInNvd.put(id, pieces[2]);
				} else {
					cvesInNvd.put(id, null);
				}
			}

			/**
			 * MITRE
			 */
			arrNVD = FileUtils.readLines(new File(mitreCvePath), "UTF-8");
			if (arrNVD.isEmpty())
				throw new IOException("Failed to read MITRE CSV file" + mitreCvePath + "... Calculations of 'not in MITRE' are going to be off");
			else
				logger.info("Successfully read in MITRE CSV file for calculations of 'not in MITRE'");
			for (String cve : arrNVD) {
				String[] pieces = cve.split(csvLogger.getSeparatorCharAsRegex());
				String id = pieces[0];
				if (pieces.length > 2) {
					cvesInMitre.put(id, pieces[2]);
				} else {
					cvesInMitre.put(id, null);
				}
			}

		} catch (IOException e) {
			logger.error("ERROR: Failed to load NVD/MITRE CVEs!\n{}\nPlease check file paths for nvd CVE and mitre CVE .csv files, " +
					"or disable it in the NVIP_REFRESH_NVD_LIST envvar", e.getMessage());
			System.exit(1); // This is a serious error, exit!
		}
		logger.info("Loaded cve data for NVD(" + cvesInNvd.size() + ") and MITRE(" + cvesInNvd.size() + ")");
	}

	/**
	 * Process CVEs to identify the ones not in NVD and MITRE
	 *
	 * @param hashMapNvipCve
	 * @return
	 */
	public HashMap<String, List<Object>> checkAgainstNvdMitre(Map<String, CompositeVulnerability> hashMapNvipCve,
															  Map<String, Vulnerability> existingCves) {

		// TODO: Grab current vulns in DB, and verify these vulns are still not in NVD before running comparison
		//  We only pull from last months CVEs for NVD, so there'll be issues if we don't compare with current records
		HashMap<String, List<Object>> newCVEMap = new HashMap<>();
		logger.info("Comparing with NVD and MITRE");
		// get list from hash map
		Set<Object> allCveData = new HashSet<>();
		Set<Object> newCVEDataNotInMitre = new HashSet<>();
		Set<Object> newCVEDataNotInNvd = new HashSet<>();

		for (CompositeVulnerability vuln : hashMapNvipCve.values()) {
			try {
				// If somehow a wrong CVE id is found, ignore it
				if (!cveUtils.isCveIdCorrect(vuln.getCveId())) {
					String note = "Wrong CVE ID! Check for typo? ";
					vuln.setNvipNote(note);
					logger.warn("WARNING: The CVE ID {} found at {} does not appear to be valid!", vuln.getCveId(), Arrays.deepToString(vuln.getSourceURL().toArray()));
					continue;
				}

				allCveData.add(vuln);

				if (vuln.isFoundNewDescriptionForReservedCve()) {
					logger.info("CVE: {} has new description for Reserved Cve", vuln.getCveId());
					vuln.setMitreStatus(1);
					vuln.setNvdStatus(1);
					continue;
				}


				if (cvesInNvd.containsKey(vuln.getCveId())){
					logger.info("CVE: {} is in NVD: Setting status to 1", vuln.getCveId());
					vuln.setNvdStatus(1);
				} else if (existingCves.containsKey(vuln.getCveId()) && existingCves.get(vuln.getCveId()).getNvdStatus() == 0) {
					long monthsBetween = ChronoUnit.MONTHS.between(LocalDateTime.now(), existingCves.get(vuln.getCveId()).getCreatedDateAsDate());
					if (monthsBetween <= 1 && monthsBetween >= 0) {
						logger.info("CVE: {}, is in NVIP and NOT in NVD", vuln.getCveId());
						vuln.setNvdSearchResult("NA");
						vuln.setNvdStatus(0);
						newCVEDataNotInNvd.add(vuln);
					} else {
						logger.info("CVE: {} is from over a month ago, will assume it's in NVD: Setting status to 1", vuln.getCveId());
						vuln.setNvdStatus(1);
					}
				} else if (!existingCves.containsKey(vuln.getCveId())) {
					logger.info("CVE: {} is NOT in NVIP and NOT in NVD: Keeping status as 0", vuln.getCveId());
					vuln.setNvdSearchResult("NA");
					vuln.setNvdStatus(0);
					newCVEDataNotInNvd.add(vuln);
				} else {
					logger.info("CVE: {} is already in NVIP and is in NVD: Keeping status as 1", vuln.getCveId());
					vuln.setNvdStatus(1);
				}

				if (cvesInMitre.containsKey(vuln.getCveId())){
					logger.info("CVE: {} is in Mitre: Setting status to 1", vuln.getCveId());
					vuln.setMitreStatus(1);
				} else if (existingCves.containsKey(vuln.getCveId()) && existingCves.get(vuln.getCveId()).getMitreStatus() == 0) {
					long monthsBetween = ChronoUnit.MONTHS.between(LocalDateTime.now(),existingCves.get(vuln.getCveId()).getCreatedDateAsDate());
					if (monthsBetween <= 1 && monthsBetween >= 0) {
						logger.info("CVE: {}, is NOT in Mitre", vuln.getCveId());
						vuln.setMitreSearchResult("NA");
						vuln.setMitreStatus(0);
						newCVEDataNotInMitre.add(vuln);
					} else {
						logger.info("CVE: {} is from over a month ago, will assume it's in MITRE: Setting status to 1", vuln.getCveId());
						vuln.setMitreStatus(1);
					}
				} else if (!existingCves.containsKey(vuln.getCveId())) {
					logger.info("CVE: {} is not in NVIP and not in MITRE: Keeping status as 0", vuln.getCveId());
					vuln.setMitreSearchResult("NA");
					vuln.setMitreStatus(0);
					newCVEDataNotInMitre.add(vuln);
				} else {
					logger.info("CVE: {} is already in DB and is in MITRE: Keeping status as 1", vuln.getCveId());
					vuln.setMitreStatus(1);
				}

			} catch (Exception e) {
				logger.error("ERROR: Error while checking against NVD/MITRE, CVE: {}\n{}", vuln.getCveId(), e.toString());
			}
		}

		newCVEMap.put("all", Arrays.asList(allCveData.toArray())); // all CVEs
		newCVEMap.put("mitre", Arrays.asList(newCVEDataNotInMitre.toArray())); // CVEs not in Mitre
		newCVEMap.put("nvd", Arrays.asList(newCVEDataNotInNvd.toArray())); // CVEs not in Nvd
		newCVEMap.put("nvd-mitre", Arrays.asList(SetUtils.intersection(newCVEDataNotInMitre, newCVEDataNotInNvd).toArray())); // CVEs not in Nvd and Mitre

		logger.info("Out of {} total valid CVEs crawled: \n{} does not appear in NVD, \n{} does not appear in MITRE and \n{} are not in either!",
				newCVEMap.get(ALL_CVE_KEY).size(),
				newCVEMap.get(NVD_CVE_KEY).size(),
				newCVEMap.get(MITRE_CVE_KEY).size(),
				newCVEMap.get(NVD_MITRE_CVE_KEY).size());

		return newCVEMap;
	}

	/**
	 * Calculate Time Gaps between NVD by comparing the
	 * current date with the date the CVE was created in NVIP
	 *
	 * This is for CVEs that changed NVD status to exists_in_nvd,
	 * hence this is when NVD adds the vulnerability
	 * @param hashMapNvipCve
	 * @return
	 */
	public HashMap<String, List<Object>> checkTimeGaps(Map<String, List<Object>> hashMapNvipCve, Map<String, Vulnerability> existingCves) {

		logger.info("Calculating Time Gaps for NVD...");

		for (Object cveInNvd: hashMapNvipCve.get(ALL_CVE_KEY)) {
			CompositeVulnerability cve = (CompositeVulnerability) cveInNvd;
			if (!hashMapNvipCve.get(NVD_CVE_KEY).contains(cve)) {
				if (existingCves.containsKey(cve.getCveId())) {
					Vulnerability existingCveAttributes = existingCves.get(cve.getCveId());

					if (existingCveAttributes.getNvdStatus() == 0 && cve.getNvdStatus() == 1) {
						try {
							logger.info("Calculating NVD Time Gap for {}", cve.getCveId());
							LocalDateTime createdDate = existingCveAttributes.getCreatedDateAsDate();
							LocalDateTime currentCreateDate = cve.getCreatedDateAsDate();

							int timeGapNvd = (int) Duration.between(createdDate, currentCreateDate).toHours();
							cve.setTimeGapNvd(timeGapNvd);
						} catch (Exception e) {
							logger.error("ERROR: Failed to calculate Time Gap for CVE: {}\n{}", cve.getCveId(), e);
						}
					}
				}
			}

		}

		return (HashMap<String, List<Object>>) hashMapNvipCve;
	}
}
