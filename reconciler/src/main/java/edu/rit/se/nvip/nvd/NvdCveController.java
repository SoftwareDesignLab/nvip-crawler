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
import edu.rit.se.nvip.model.NvdVulnerability;
import edu.rit.se.nvip.reconciler.Reconciler;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.http.HttpConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 
 * The main class for NVD feed reader
 * 
 * @author axoeec
 *
 */

public class NvdCveController {
	private final Logger logger = LogManager.getLogger(NvdCveController.class);

	private static DatabaseHelper dbh;
	private final String startDate;
	private final String endDate;
	private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");
	private String nvdApiUrl;
	private HttpURLConnection conn;
	private URL url;
	private BufferedReader br;


	/**
	 * Constructor for NvdCveController
	 * Sets today and last month's times on construction
	 */
	public NvdCveController() {
		this(ReconcilerEnvVars.getNvdApiUrl(), LocalDateTime.now().minusDays(30), LocalDateTime.now());
	}

	public NvdCveController(String nvdApiUrl, LocalDateTime startDate, LocalDateTime endDate) {
		this.nvdApiUrl = nvdApiUrl;
		this.startDate = startDate.format(formatter);
		this.endDate = endDate.format(formatter);
	}
	public void createDatabaseInstance(){
		dbh = DatabaseHelper.getInstance();
	}
	public Set<CompositeVulnerability> compareWithNvd(Set<CompositeVulnerability> reconciledVulns) {
		Set<CompositeVulnerability> affected = dbh.attachNvdVulns(reconciledVulns); // returns the compvulns that got an nvdvuln attached
		int inNvd = (int) reconciledVulns.stream().filter(CompositeVulnerability::isInNvd).count(); // let the compvuln decide for itself if it's in nvd
		int notInNvd = reconciledVulns.size() - inNvd;
		Set<NvdVulnerability> nvdVulns = affected.stream().map(CompositeVulnerability::getNvdVuln).collect(Collectors.toSet()); // pull out the matching nvdvulns
		Map<NvdVulnerability.NvdStatus, Integer> statusToCount = new HashMap<>();
		for (NvdVulnerability nvdVuln : nvdVulns) { // iterate through each nvd vuln and update appropriate counters. better than 4 filter streams
			NvdVulnerability.NvdStatus status = nvdVuln.getStatus();
			if (statusToCount.containsKey(status)) {
				statusToCount.put(status, statusToCount.get(status)+1);
			} else {
				statusToCount.put(status, 1);
			}
		}

		int numAnalyzed = 0;
		int numReceived = 0;
		int numUndergoing = 0;
		int numAwaiting = 0;
		if(statusToCount.get(NvdVulnerability.NvdStatus.ANALYZED) != null) numAnalyzed = statusToCount.get(NvdVulnerability.NvdStatus.ANALYZED);
		if(statusToCount.get(NvdVulnerability.NvdStatus.RECEIVED) != null) numReceived = statusToCount.get(NvdVulnerability.NvdStatus.RECEIVED);
		if(statusToCount.get(NvdVulnerability.NvdStatus.UNDERGOING_ANALYSIS) != null) numUndergoing = statusToCount.get(NvdVulnerability.NvdStatus.UNDERGOING_ANALYSIS);
		if(statusToCount.get(NvdVulnerability.NvdStatus.AWAITING_ANALYSIS) != null) numAwaiting = statusToCount.get(NvdVulnerability.NvdStatus.AWAITING_ANALYSIS);

		logger.info("NVD Comparison Results\n" +
						"{} in NVD\n" +
						"{} not in NVD\n" +
						"{} analyzed in NVD\n" +
						"{} received by NVD\n" +
						"{} undergoing analysis in NVD\n" +
						"{} awaiting analysis in NVD",
				inNvd, notInNvd,
				numAnalyzed,
				numReceived,
				numUndergoing,
				numAwaiting
		);

		return affected;
	}

	public void updateNvdTables() {
		Set<NvdVulnerability> nvdCves = fetchCvesFromNvd(nvdApiUrl.replaceAll("<StartDate>", this.startDate)
				.replaceAll("<EndDate>", this.endDate));

		logger.info("Grabbed {} cves from NVD for the past month", nvdCves.size());
		Set<NvdVulnerability> toBackfill = dbh.upsertNvdData(nvdCves); // return the ones that were inserted/updated
		logger.info("Inserted {} new CVEs from NVD into NVD Database Table", toBackfill.size());
		dbh.backfillNvdTimegaps(toBackfill); // todo return number of time gaps
	}


	/**
	 * For grabbing NVD cves from the past month
	 * @param nvdUrl
	 * @return
	 */
	private Set<NvdVulnerability> fetchCvesFromNvd(String nvdUrl) {
		Set<NvdVulnerability> nvdCves = new HashSet<>();
		try {
			if(url == null){
				url = new URL(nvdUrl);
			}
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setRequestProperty("Accept", "application/json");

			if (conn.getResponseCode() != 200) {
				logger.error("Failed to connect to NVD API. Error Code: {}", conn.getResponseCode());
				throw new RuntimeException("Failed : HTTP error code : " + conn.getResponseCode());
			} else {

				if(br == null) {
					br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
				}
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
					Timestamp pubTime = Timestamp.valueOf(LocalDateTime.parse(publishedDate, formatter));
					nvdCves.add(new NvdVulnerability(cveId, pubTime, status));
				}
			}
		} catch (IOException e) {
			logger.error("ERROR: Failed to grab CVEs from NVD: {}", e.getMessage());
		}

		return nvdCves;
	}
	public void setDatabaseHelper(DatabaseHelper dbHelper){
		dbh = dbHelper;
	}

	public void setUrl(URL nvdUrl){
		url = nvdUrl;
	}

	public void setBr(BufferedReader bfr){
		br = bfr;
	}
}
