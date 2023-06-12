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
package nvd;

import edu.rit.se.nvip.DatabaseHelper;
import model.CompositeVulnerability;
import model.NvdVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

/**
 * 
 * The main class for NVD feed reader
 * 
 * @author axoeec
 *
 */

public class NvdCveController {
	private final Logger logger = LogManager.getLogger(NvdCveController.class);
	private static DatabaseHelper databaseHelper;
	private String startDate;
	private String endDate;

	public static void main(String[] args) {
		NvdCveController nvd = new NvdCveController();
		//nvd.updateNvdDataTable("https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=<StartDate>&pubEndDate=<EndDate>");
		//nvd.compareReconciledCVEsWithNVD();
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
	 * @param vulns
	 */
	public Set<CompositeVulnerability> compareReconciledCVEsWithNVD(Set<CompositeVulnerability> vulns) {
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

		// For each composite vulnerability, iterate through NVD vulns to see if there's a match in the CVE IDs
		// If there's a match, check status of the CVE in NVD, otherwise mark it as not in NVD
		for (CompositeVulnerability vuln: vulns) {
			boolean checked = false;

			for (NvdVulnerability nvdCve: nvdCves) {

				if (checked)
					break;

				if (nvdCve.getCveId().equals(vuln.getCveId())) {
					switch (nvdCve.getStatus()) {
						case "Received": {
							received++;
							notInNvd++;
							checked = true;
							break;
						}
						case "Undergoing Analysis": {
							underGoingAnalysis++;
							notInNvd++;
							checked = true;
							break;
						}
						case "Awaiting Analysis": {
							awaitingAnalysis++;
							notInNvd++;
							checked = true;
							break;
						}
						case "Analyzed": {
							analyzed++;
							inNvd++;
							checked = true;
							vuln.setNvdStatus(CompositeVulnerability.NvdStatus.IN_NVD);
							break;
						}
						default: {
							break;
						}
					}
				}
			}

			if (!checked) {
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


		return vulns;
	}

	/**
	 * For updating NVD table with recent CVEs
	 * Grabs CVEs via API request to NVD API
	 *
	 * TODO: Need to add logic for checking if a vulnerability is already in the table, then update status if needed
	 *
	 * @param url
	 */
	public void updateNvdDataTable(String url) {
		// fetch the CVEs from NVD
		Set<NvdVulnerability> NvdCves = fetchCvesFromNvd(url.replaceAll("<StartDate>", this.startDate)
				.replaceAll("<EndDate>", this.endDate));

		logger.info("Grabbed {} cves from NVD for the past month", NvdCves.size());

		int totalUpdated = 0;

		for (NvdVulnerability NvdCve: NvdCves) {
			totalUpdated += databaseHelper.insertNvdCve(NvdCve);
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
					nvdCves.add(new NvdVulnerability(cveId, LocalDateTime.parse(publishedDate.substring(0, 16) + ":00"), status));
				}
			}
		} catch (IOException e) {
			logger.error("ERROR: Failed to grab CVEs from NVD: {}", e.getMessage());
		}

		return nvdCves;
	}


}
