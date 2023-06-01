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
import java.util.*;

import edu.rit.se.nvip.model.*;
import org.apache.commons.collections4.SetUtils;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.cvereconcile.CveReconciler;
import edu.rit.se.nvip.utils.CsvUtils;

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

	/**
	 * Old hashmap used for CVEs in NVD, remove this
	 */
	private Map<String, String> cvesInNvd = new HashMap<>();

	/**
	 * New hashmap for CVEs in NVD
	 */
	private HashMap<String, NvdVulnerability> nvdCVEs;
	private Map<String, String> cvesInMitre = new HashMap<>();

	/**
	 * New hashmap for CVEs in Mitre
	 */
	private HashMap<String, MitreVulnerability> mitreCves;

	CveReconciler cveUtils = new CveReconciler();

	/**
	 * For tests
	 *
	 * @param nvdCves
	 * @param mitreCves
	 * @param pulledMitreCves
	 */
	public CveProcessor(HashMap<String, String> nvdCves, HashMap<String, String> mitreCves,
						HashMap<String, NvdVulnerability> pulledNvdCves, HashMap<String, MitreVulnerability> pulledMitreCves){
		this.cvesInNvd = nvdCves;
		this.cvesInMitre = mitreCves;
		this.nvdCVEs = pulledNvdCves;
		this.mitreCves = pulledMitreCves;
	}

	/**
	 * Constructor for processor class
	 * @param nvdCvePath --> File path to NVD CVE .csv file (not used anymore)
	 * @param mitreCvePath --> File path to MITRE CVE .csv file
	 * @param nvdCves --> Hashmap of CVEs in NVD (provided byb NVD Controller class)
	 */
	public CveProcessor(String nvdCvePath, String mitreCvePath, HashMap<String, NvdVulnerability> nvdCves, HashMap<String, MitreVulnerability> mitreCves) {

		this.nvdCVEs = nvdCves;
		this.mitreCves = mitreCves;

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

		HashMap<String, List<Object>> newCVEMap = new HashMap<>();
		logger.info("Comparing with NVD and MITRE");
		// get list from hash map
		Set<Object> allCveData = new HashSet<>();
		Set<Object> newCVEDataNotInMitre = new HashSet<>();
		Set<Object> newCVEDataNotInNvd = new HashSet<>();

		// For tracking total CVEs for each status
		int nvdReceived = 0;
		int nvdUndergoingAnalysis = 0;
		int nvdAwaitingAnalysis = 0;
		int nvdOther = 0;

		for (CompositeVulnerability vuln : hashMapNvipCve.values()) {
			try {
				// If somehow a wrong CVE id is found, ignore it
				if (!cveUtils.isCveIdCorrect(vuln.getCveId())) {
					String note = "Wrong CVE ID! Check for typo?";
					vuln.setNvipNote(note);
					logger.warn("WARNING: The CVE ID {} found at {} does not appear to be valid!", vuln.getCveId(), Arrays.deepToString(vuln.getSourceURL().toArray()));
					continue;
				}

				allCveData.add(vuln);

				// Compare w/ NVD
				if (nvdCVEs.containsKey(vuln.getCveId())){
					// Check status of CVE in NVD, if RECEIVED, then it is in NVD.
					// If any other status, then it is not in NVD.
					if (nvdCVEs.get(vuln.getCveId()).getStatus() == NvdVulnerability.nvdStatus.NOTINNVD) {
						vuln.setNvdStatus(0);
						newCVEDataNotInNvd.add(vuln);
					} else {
						vuln.setNvdStatus(1);

						// Update count for status'
						nvdReceived = nvdCVEs.get(vuln.getCveId()).getStatus() == NvdVulnerability.nvdStatus.RECEIVED ? nvdReceived + 1 : nvdReceived;
						nvdUndergoingAnalysis = nvdCVEs.get(vuln.getCveId()).getStatus() == NvdVulnerability.nvdStatus.UNDERGOINGANALYSIS ? nvdUndergoingAnalysis + 1 : nvdUndergoingAnalysis;
						nvdAwaitingAnalysis = nvdCVEs.get(vuln.getCveId()).getStatus() == NvdVulnerability.nvdStatus.AWAITINGANALYSIS ? nvdAwaitingAnalysis + 1 : nvdAwaitingAnalysis;
						nvdOther = nvdCVEs.get(vuln.getCveId()).getStatus() == NvdVulnerability.nvdStatus.NOTINNVD ? nvdOther + 1 : nvdOther;
					}
				} else if (existingCves.containsKey(vuln.getCveId()) && existingCves.get(vuln.getCveId()).getNvdStatus() == 1) {
					vuln.setNvdStatus(1);
				} else {
					logger.info("CVE: {}, is NOT in NVD", vuln.getCveId());
					vuln.setNvdSearchResult("NA");
					vuln.setNvdStatus(0);
					newCVEDataNotInNvd.add(vuln);
				}


				// Compare w/ MITRE
				if (mitreCves.containsKey(vuln.getCveId())){
					// Check status of CVE in MITRE, if PUBLIC or PUBLISHED, then it is in MITRE.
					// If any other status, then it is not in MITRE.
					if (mitreCves.get(vuln.getCveId()).getStatus() == MitreVulnerability.mitreStatus.NOTINMITRE ||
							mitreCves.get(vuln.getCveId()).getStatus() == MitreVulnerability.mitreStatus.RESERVED) {
						vuln.setMitreStatus(0);
						newCVEDataNotInMitre.add(vuln);
					} else {
						vuln.setMitreStatus(1);
					}
				} else if (existingCves.containsKey(vuln.getCveId()) && existingCves.get(vuln.getCveId()).getMitreStatus() == 1) {
					vuln.setMitreStatus(1);
				} else {
					logger.info("CVE: {}, is NOT in MITRE", vuln.getCveId());
					vuln.setMitreSearchResult("NA");
					vuln.setMitreStatus(0);
					newCVEDataNotInMitre.add(vuln);
				}

			} catch (Exception e) {
				logger.error("ERROR: Error while checking against NVD/MITRE, CVE: {}\n{}", vuln.getCveId(), e.toString());
			}
		}

		newCVEMap.put(ALL_CVE_KEY, Arrays.asList(allCveData.toArray())); // all CVEs
		newCVEMap.put(MITRE_CVE_KEY, Arrays.asList(newCVEDataNotInMitre.toArray())); // CVEs not in Mitre
		newCVEMap.put(NVD_CVE_KEY, Arrays.asList(newCVEDataNotInNvd.toArray())); // CVEs not in Nvd
		newCVEMap.put(NVD_MITRE_CVE_KEY, Arrays.asList(SetUtils.intersection(newCVEDataNotInMitre, newCVEDataNotInNvd).toArray())); // CVEs not in Nvd and Mitre

		logger.info("Out of {} total valid CVEs crawled: \n{} does not appear in NVD or are rejected, \n{} does not appear in MITRE and \n{} are not in either!",
				newCVEMap.get(ALL_CVE_KEY).size(),
				newCVEMap.get(NVD_CVE_KEY).size(),
				newCVEMap.get(MITRE_CVE_KEY).size(),
				newCVEMap.get(NVD_MITRE_CVE_KEY).size());

		logger.info("Amongst the CVEs in NVD: \n{} are RECEIVED\n{} are UNDERGOING ANALYSIS\n{} are AWAITING ANALYSIS" +
				"\n{} are either a different status or not in NVD", nvdReceived, nvdUndergoingAnalysis, nvdAwaitingAnalysis, nvdOther);

		return newCVEMap;
	}

	/**
	 * Calculate Time Gaps between NVD by comparing the
	 * current date with the date the CVE was created in NVIP
	 *
	 * This is for CVEs that changed NVD status to exists_in_nvd,
	 * hence this is when NVD adds the vulnerability
	 *
	 * Note this only checks time gaps between NVIP and NVD, MITRE time gaps are not calculated (yet)
	 *
	 * @param hashMapNvipCve
	 * @return
	 */
	public HashMap<String, List<Object>> checkTimeGaps(Map<String, List<Object>> hashMapNvipCve, Map<String, Vulnerability> existingCves) {

		logger.info("Calculating NVD Time Gaps for {} CVEs", hashMapNvipCve.get(ALL_CVE_KEY).size() - hashMapNvipCve.get(NVD_CVE_KEY).size());
		logger.info("Calculating NVD Time Gaps for {} CVEs", hashMapNvipCve.get(ALL_CVE_KEY).size() - hashMapNvipCve.get(MITRE_CVE_KEY).size());

		for (Object cveInNvd: hashMapNvipCve.get(ALL_CVE_KEY)) {
			CompositeVulnerability cve = (CompositeVulnerability) cveInNvd;

			// Check if CVE is in NVD, and make sure the CVE is for the current year. Anything from previous
			// years are assumed to be in NVD
			if (!hashMapNvipCve.get(NVD_CVE_KEY).contains(cve) && checkAgeOfCVEByYear(cve.getCveId())) {
				//logger.info("Checking if CVE: {} is in NVIP", cve.getCveId());
				if (existingCves.containsKey(cve.getCveId())) {
					//logger.info("CVE: {} is in NVIP, is it found in NVD?", cve.getCveId());
					Vulnerability existingCveAttributes = existingCves.get(cve.getCveId());

					// Was the CVE previously found? If so, was it not in NVD before, and is it in NVD now?
					// Compare original created date with the NVD published date
					// We'll use the NVD published date for now, since published date can refer to date the CVE is received
					// which would show an accurate difference.
					if (existingCveAttributes.getNvdStatus() == 0 && cve.getNvdStatus() == 1) {
						try {
							logger.info("Calculating NVD Time Gap for {}", cve.getCveId());
							LocalDateTime publishedDateNVD = LocalDateTime.parse(nvdCVEs.get(cve.getCveId()).getPublishDate(),
									DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS"));
							LocalDateTime existingCreatedDate = existingCveAttributes.getCreatedDateAsDate();
							int timeGapNvd = (int) Duration.between(existingCreatedDate, publishedDateNVD).toHours();

							if (timeGapNvd < 0) {
								cve.setTimeGapNvd(0);
								logger.info("Calculated Negative Time Gap: {} for CVE: {}, will setting time gap as 0", timeGapNvd, cve.getCveId());
							} else if (existingCveAttributes.getTimeGapNvd() > 0) {
								cve.setTimeGapNvd(existingCveAttributes.getTimeGapNvd());
								logger.info("CVE: {} Already has a NVD time gap of {}", cve.getCveId(), existingCveAttributes.getTimeGapNvd());
							} else {
								cve.setTimeGapNvd(timeGapNvd);
								logger.info("Calculated Time Gap: {} for CVE: {}", timeGapNvd, cve.getCveId());
							}

						} catch (Exception e) {
							logger.error("ERROR: Failed to calculate Time Gap for CVE: {}\n{}", cve.getCveId(), e);
							e.printStackTrace();
						}
					} else {
						logger.info("CVE: {} is in NVIP but not found in NVD yet", cve.getCveId());
					}
				}
			}

			// Check if CVE is in MITRE, and make sure the CVE is for the current year. Anything from previous
			// years are assumed to be in MITRE
			if (!hashMapNvipCve.get(MITRE_CVE_KEY).contains(cve) && checkAgeOfCVEByYear(cve.getCveId())) {
				if (existingCves.containsKey(cve.getCveId())) {
					Vulnerability existingCveAttributes = existingCves.get(cve.getCveId());

					// Was the CVE previously found? If so, was it not in MITRE before, and is it in MITRE now?
					// Compare original created date with the MITRE published date
					if (existingCveAttributes.getNvdStatus() == 0 && cve.getNvdStatus() == 1) {
						try {
							logger.info("Calculating MITRE Time Gap for {}", cve.getCveId());
							LocalDateTime publishedDateMITRE = LocalDateTime.parse(nvdCVEs.get(cve.getCveId()).getPublishDate(),
									DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS"));
							LocalDateTime existingCreatedDate = existingCveAttributes.getCreatedDateAsDate();
							int timeGapMitre = (int) Duration.between(existingCreatedDate, publishedDateMITRE).toHours();

							if (timeGapMitre < 0) {
								cve.setTimeGapMitre(0);
								logger.info("Calculated Negative Time Gap: {} for CVE: {}, will setting time gap as 0", timeGapMitre, cve.getCveId());
							} else if (existingCveAttributes.getTimeGapNvd() > 0) {
								cve.setTimeGapMitre(existingCveAttributes.getTimeGapNvd());
								logger.info("CVE: {} Already has a MITRE time gap of {}", cve.getCveId(), existingCveAttributes.getTimeGapNvd());
							} else {
								cve.setTimeGapMitre(timeGapMitre);
								logger.info("Calculated Time Gap: {} for CVE: {}", timeGapMitre, cve.getCveId());
							}

						} catch (Exception e) {
							logger.error("ERROR: Failed to calculate Time Gap for CVE: {}\n{}", cve.getCveId(), e);
							e.printStackTrace();
						}
					} else {
						logger.info("CVE: {} is in NVIP but not found in MITRE yet", cve.getCveId());
					}
				}
			}


		}

		return (HashMap<String, List<Object>>) hashMapNvipCve;
	}

	/**
	 * for checking the age of a CVE, if the year in the CVE isn't the currnet year,
	 * then the CVE is too old and shouldn't be compared to NVD/MITRE
	 * @param cveId
	 * @return
	 */
	public boolean checkAgeOfCVEByYear(String cveId) {
		/**
		 * We are not expecting a time gap more than 1 year. If CVE is from prior years
		 * skip time gap check
		 */
		String[] cveParts = cveId.split("-");

		if (cveParts.length <= 1) {
			logger.info("CVE: {} is not eligible for time gap checks, skipping this cve", cveId);
			return false;
		}

		int cveYear = Integer.parseInt(cveParts[1]);
		int currentYear = Calendar.getInstance().get(Calendar.YEAR);
		boolean calculateGap = (cveYear == currentYear);

		if (!calculateGap) {
			return false;
		}

		return true;
	}
}
