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
package edu.rit.se.nvip.nvd;

import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.MitreVulnerability;
import edu.rit.se.nvip.model.NvdVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 
 * The main class for NVD feed reader
 * 
 * @author axoeec
 *
 */

public class NvdCveController {
	private final Logger logger = LogManager.getLogger(NvdCveController.class);

	private static DatabaseHelper dbh = DatabaseHelper.getInstance();
	private static DatabaseHelper databaseHelper;
	private String startDate;
	private String endDate;
	private static final String nvdJsonFeedUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=<StartDate>&pubEndDate=<EndDate>";
	String[] header = new String[] { "CVE-ID", "Description", "BaseScore", "BaseSeverity", "ImpactScore", "ExploitabilityScore", "CWE", "Advisory", "Patch", "Exploit" };
	private DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'hh:mm:ss");

	boolean logCPEInfo = true;

	/**
	 * for testing NVD CVE pull
	 * @param args
	 */
	public static void main(String[] args) {
//		NvdCveController nvd = new NvdCveController();
//		//nvd.updateNvdDataTable("https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=<StartDate>&pubEndDate=<EndDate>");
//		//nvd.compareReconciledCVEsWithNVD();
//		HashMap<String, NvdVulnerability> nvdCves = nvd.fetchNVDCVEs(
//				"https://services.nvd.nist.gov/rest/json/cves/2.0?pubstartDate=<StartDate>&pubEndDate=<EndDate>", 10);
//		for (String cve: nvdCves.keySet()) {
//			if (nvdCves.get(cve).getStatus() == NvdVulnerability.nvdStatus.RECEIVED)
//				System.out.println(nvdCves.get(cve));
//		}
	}


	/**
	 * Constructor for NvdCveController
	 * Sets today and last month's times on construction
	 */
	public NvdCveController() {
		LocalDateTime today = LocalDateTime.now();
		LocalDateTime lastMonth = LocalDateTime.now().minusDays(30);
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'hh:mm:ss");

		this.startDate = lastMonth.format(formatter);
		this.endDate = today.format(formatter);

		databaseHelper = DatabaseHelper.getInstance();
	}

	/**
	 * For comparing Reconciled CVEs with NVD,
	 * Grabs CVEs from nvddata table to run comparison
	 *
	 * Calculates # of CVEs not in NVD, as well as average time gaps
	 *
	 * @param reconciledVulns
	 */
	public void compareReconciledCVEsWithNVD(Set<CompositeVulnerability> reconciledVulns) {
		// Get NVD CVEs
		ArrayList<NvdVulnerability> nvdCves = databaseHelper.getAllNvdCVEs();

		//Run comparison by iterating raw CVEs
		int inNvd = 0;
		int notInNvd = 0;
		int received = 0;
		int analyzed = 0;
		int awaitingAnalysis = 0;
		int underGoingAnalysis = 0;

		double avgTimeGap = 0;

		logger.info("Comparing with NVD, this may take some time....");

		Map<String, NvdVulnerability> idToVuln = new HashMap<>();
		nvdCves.forEach(v -> idToVuln.put(v.getCveId(), v));

		for (CompositeVulnerability compVuln : reconciledVulns) {
			if (idToVuln.containsKey(compVuln.getCveId())) {
				NvdVulnerability nvdVuln = idToVuln.get(compVuln.getCveId());
				switch (idToVuln.get(compVuln.getCveId()).getStatus()) {
					case RECEIVED: {
						received++;
						notInNvd++;
						break;
					}
					case UNDERGOINGANALYSIS: {
						underGoingAnalysis++;
						notInNvd++;
						break;
					}
					case AWAITINGANALYSIS: {
						awaitingAnalysis++;
						notInNvd++;
						break;
					}
					case ANALYZED: {
						analyzed++;
						inNvd++;
						compVuln.setInNvd(1);
						double timeGap = Math.max((nvdVuln.getPublishDate().getTime() - compVuln.getCreateDate().getTime())/3600./1000., 0);
						compVuln.setTimeGapNvd(timeGap);
						break;
					}
					default: {
						break;
					}
				}
			} else {
				notInNvd++;
			}
		}

		//Print Results
		logger.info("NVD Comparison Results\n" +
				"{} in NVD\n" +
				"{} not in NVD\n" +
				"{} analyzed in NVD\n" +
				"{} received by NVD\n" +
				"{} undergoing analysis in NVD\n" +
				"{} awaiting analysis in NVD",
				inNvd, notInNvd, analyzed, received, underGoingAnalysis, awaitingAnalysis);

	}

	/**
	 * For updating NVD table with recent CVEs
	 * Grabs CVEs via API request to NVD API
	 *
	 * TODO: Need to add logic for checking if a vulnerability is already in the table, then update status if needed
	 *
	 * @param url
	 */
	/**
	 * For grabbing CVEs from NVD via NVD's API
	 * @param nvdApiPath
	 * @return
	 */
	public HashMap<String, NvdVulnerability> fetchNVDCVEs(String nvdApiPath, int requestLimit) {
		HashMap<String, NvdVulnerability> NvdCves = new HashMap<>();
		int resultsPerPage = 2000;
		int startIndex = 0;
		int requestNum = 0;

		String currentRequestString = nvdApiPath.replaceAll("<StartDate>", this.startDate).replaceAll("<EndDate>", this.endDate);

		while (requestNum < requestLimit) {
			// 30 second wait for every 5 requests, according to NVD Doc: https://nvd.nist.gov/developers/start-here
			if (requestNum % 5 == 0 && requestNum > 0) {
				logger.info("Sleeping for 60 seconds before continuing");
				try {
					Thread.sleep(60000);
				} catch (InterruptedException e) {
					logger.error("ERROR: Failed to wait 30seconds for pulling NVD CVEs\n{}", e);
				}
			}

			try {
				// Pull from NVD, keep track of startIndex for paginating response
				String url = currentRequestString + "&resultsPerPage=" + resultsPerPage + "&startIndex=" + startIndex;
				URL apiUrl = new URL(url);
				HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
				connection.setRequestMethod("GET");

				if (connection.getResponseCode() != 200) {
					logger.error("Error retrieving CVEs with URL {}\nResponse Code: {}\n{}", url, connection.getResponseCode(), connection.getResponseMessage());
					break;
				}

				logger.info("Connection Acquired for URL {}", url);

				requestNum++;

				// Parse response to JSON
				StringBuilder response = new StringBuilder();
				BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
				String line;
				while ((line = reader.readLine()) != null) {
					response.append(line);
					response.append(System.lineSeparator()); // Add line separator if needed
				}
				reader.close();

				JSONObject cveData = new JSONObject(response.toString());

				JSONArray vulnerabilities = cveData.getJSONArray("vulnerabilities");
				if (vulnerabilities.length() == 0) {
					logger.info("No more CVEs in response, list is empty");
					break;
				}

				// for each vulnerability in response list, add cveId, publishedDate and status to the hashmap
				for (int i = 0; i < vulnerabilities.length(); i++) {
					JSONObject cve = vulnerabilities.getJSONObject(i);

					String cveId = cve.getJSONObject("cve").getString("id");
					String publishedDate = cve.getJSONObject("cve").getString("published");
					String lastModifiedDate = cve.getJSONObject("cve").getString("lastModified");
					String status = cve.getJSONObject("cve").getString("vulnStatus");

//					logger.info("CVE ID: {}", cveId);
//					logger.info("Published Date: {}", publishedDate);
//					logger.info("Status: {}", status);

					NvdCves.put(cveId, new NvdVulnerability(cveId, Timestamp.valueOf(publishedDate),  Timestamp.valueOf(lastModifiedDate), status));
				}

				logger.info("{} Total CVEs", NvdCves.size());

				// Check if there's more CVEs to pull, otherwise break and return the data
				int totalResults = cveData.getInt("totalResults");
				startIndex += cveData.getInt("resultsPerPage");

				// If we've reached the total results for the response, move the start and end dates back by 119 days
				// We must adhere to the 120 day range limit in NVD's API for specifying date ranges
				if (startIndex >= totalResults) {
					startIndex = 0;
					this.endDate = this.startDate;
					this.startDate = LocalDateTime.parse(this.endDate).minusDays(119).format(formatter);
					currentRequestString = nvdApiPath.replaceAll("<StartDate>", this.startDate).replaceAll("<EndDate>", this.endDate);
				}

				connection.disconnect();
			} catch (IOException e) {
				logger.error("ERROR: Failed to parse CVEs form NVD\n{}", e.toString());
				break;
			}
		}

		return NvdCves;
	}

	/**
	 * Updates Nvd Data Table based on string URL
	 * @param url
	 */
	public void updateNvdDataTable(String url) {
		// fetch the CVEs from NVD
		Set<NvdVulnerability> NvdCves = fetchCvesFromNvd(url.replaceAll("<StartDate>", this.startDate)
				.replaceAll("<EndDate>", this.endDate));

		logger.info("Grabbed {} cves from NVD for the past month", NvdCves.size());

		int totalUpdated = 0;

		for (NvdVulnerability NvdCve: NvdCves) {
			totalUpdated += databaseHelper.updateNvdData(NvdCve, false);
		}

		logger.info("Inserted {} new CVEs from NVD into NVD Database Table", totalUpdated);
	}


	/**
	 * For grabbing NVD cves from the past month
	 * @param nvdUrl
	 * @return
	 */
	private Set<NvdVulnerability> fetchCvesFromNvd(String nvdUrl) {
		Set<NvdVulnerability> nvdCves = new HashSet<>();
		try {
			URL url = new URL(nvdUrl);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setRequestProperty("Accept", "application/json");

			if (conn.getResponseCode() != 200) {
				logger.error("Failed to connect to NVD API. Error Code: {}", conn.getResponseCode());
				throw new RuntimeException("Failed : HTTP error code : " + conn.getResponseCode());
			} else {

				BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));

				StringBuilder responseBuilder = new StringBuilder();
				String output;
				while ((output = br.readLine()) != null) {
					responseBuilder.append(output);
				}

				conn.disconnect();

				JSONObject jsonResponse = new JSONObject(responseBuilder.toString());
				JSONArray cveItems = jsonResponse.getJSONArray("vulnerabilities");

				for (int i = 0; i < cveItems.length(); i++) {
					JSONObject cveItem = cveItems.getJSONObject(i);
					JSONObject cve = cveItem.getJSONObject("cve");
					String cveId = cve.getString("id");
					String publishedDate = cve.getString("published");
					String status = cve.getString("vulnStatus");

					// Adjust published date substring to be mySql acceptable
					nvdCves.add(new NvdVulnerability(cveId, Timestamp.valueOf(publishedDate), status));
				}
			}
		} catch (IOException e) {
			logger.error("ERROR: Failed to grab CVEs from NVD: {}", e.getMessage());
		}

		return nvdCves;
	}


}
