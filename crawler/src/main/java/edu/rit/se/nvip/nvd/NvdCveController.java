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
import java.util.HashMap;

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
		//nvd.compareRawDescriptionsWithNVD();
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

	public void compareRawCVEsWithNVD() {
		// Get raw CVE ID and Created date
		HashMap<String, LocalDateTime> rawCves = new HashMap<>();

		// Get NVD CVEs
		HashMap<String, LocalDateTime> nvdCves = new HashMap<>();

		//Run comparison by iterating raw CVEs
		int notInNvd = 0;
		double avgTimeGap = 0;


		for (String rawCve: rawCves.keySet()) {
			if (nvdCves.containsKey(rawCve)) {

			} else {

			}
		}

		//Print Results

	}

	public void updateNvdDataTable(String url) {
		// fetch the CVEs from NVD
		HashMap<String, String> cves = fetchCvesFromNvd(url.replaceAll("<StartDate>", this.startDate)
				.replaceAll("<EndDate>", this.endDate));

		logger.info("Grabbed {} cves from NVD for the past month", cves.size());

		int totalUpdated = 0;

		for (String cveId: cves.keySet()) {
			totalUpdated += databaseHelper.insertNvdCve(cveId, cves.get(cveId));
		}

		logger.info("Inserted {} new CVEs from NVD into NVD Database Table", totalUpdated);
	}

	private HashMap<String, String> fetchCvesFromNvd(String nvdUrl) {
		HashMap<String, String> nvdCves = new HashMap<>();
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

					// Adjust published date substring to be mySql acceptable
					nvdCves.put(cveId, publishedDate.substring(0, 10) + " " + publishedDate.substring(11, 16) + ":00");
				}
			}
		} catch (IOException e) {
			logger.error("ERROR: Failed to grab CVEs from NVD: {}", e.getMessage());
		}

		return nvdCves;
	}


}
