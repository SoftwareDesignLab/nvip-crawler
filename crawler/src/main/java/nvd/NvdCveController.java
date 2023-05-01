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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import db.DatabaseHelper;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.egit.github.core.util.UrlUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import utils.CsvUtils;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
	private static final String nvdJsonFeedUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=<StartDate>&pubEndDate=<EndDate>";

	boolean logCPEInfo = true;

	private String startDate;
	private String endDate;

	public static void main(String[] args) {
		NvdCveController nvd = new NvdCveController();
		JsonArray list = nvd.pullCVEs();
		List<String[]> cves = new NvdCveParser().parseCVEs(list);
		CsvUtils csv = new CsvUtils();
		csv.writeListToCSV(cves, "test.csv", true);
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

	public void updateNvdDataTable(String url) {
		String nvdUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=" + startDate + "&pubEndDate=" + endDate;
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



	/**
	 * Main method of NVD_CVE_Reader
	 *
	 */
	public int pullNvdCve() {
		//CsvUtils csvLogger = new CsvUtils(); // create output CSV file and append header

		logger.info("Pulling NVD to update NVD Data table. This may take a moment...");

//		csvLogger.writeHeaderToCSV(filepath, header, false);

		// Pull yearly CVE data from NVD
		NvdCveParser myCVEParser = new NvdCveParser(); // init parser
		int totCount = 0;

		Map<String, Integer> nvdRefUrlHash = new HashMap<>();
		Map<String, List<String>> nvdCveCpeHashMap = new HashMap<>();

		try {
			// get all CVEs
			JsonArray jsonList = pullCVEs();
			List<String[]> listCVEData = myCVEParser.parseCVEs(jsonList);
			logger.info("Pulled {} CVEs", listCVEData.size());

			// write annotated descriptions to CSV
			int count = csvLogger.writeListToCSV(listCVEData, filepath, true);
			totCount += count;
			if (count > 0) {
				logger.info("Wrote {} entries to CSV file: {}", count, filepath);
			}


		} catch (Exception e) {
			String url = nvdJsonFeedUrl.replaceAll("<StartDate>", this.startDate).replaceAll("<EndDate>", this.endDate);
			logger.error("ERROR: Failed to pull NVD CVES for year {}, url: {}\n{}", this.startDate, url, e.getMessage());
		}

		logger.info("Wrote a total of *** {} *** entries to CSV file: {}", totCount, filepath);

		logCPEInfo(filepath, nvdCveCpeHashMap);

		return totCount;
	}

	/**
	 * get CVEs as JSON object from NVD for <year>
	 * 
	 * @return list of JSON objects (one json object for each json file in the zip)
	 */
	private JsonArray pullCVEs() {
		String sURL = nvdJsonFeedUrl.replaceAll("<StartDate>", this.startDate).replaceAll("<EndDate>", this.endDate);
		JsonObject json = new JsonObject();
		StringBuilder sBuilder= new StringBuilder();;

		try {
			URL url = new URL(sURL);
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			con.setRequestMethod("GET");
			BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String inputLine;
			while ((inputLine = reader.readLine()) != null) {
				sBuilder.append(inputLine);
			}
			reader.close();
			json = JsonParser.parseString(sBuilder.toString()).getAsJsonObject();
			con.disconnect();
		} catch (Exception e) {
			logger.error("Exception while reading feed from :" + sURL + "\nDetails:" + e);
		}

		return json.getAsJsonArray("vulnerabilities"); // the list includes a json object for each json file in the zip
	}

	/**
	 * log CPE info
	 * 
	 * @param cpeMap
	 */
	private void logCPEInfo(String filepath, Map<String, List<String>> cpeMap) {
		if (logCPEInfo) {
			filepath += "-CPE.csv";
			// new file object
			File file = new File(filepath);

			try (BufferedWriter bf = new BufferedWriter(new FileWriter(file))) {
				for (Map.Entry<String, List<String>> entry : cpeMap.entrySet()) {
					StringBuilder sCpe = new StringBuilder();
					for (String cpe : entry.getValue()) {
						sCpe.append(cpe.replace(",", "")).append(" ");
					}
					bf.write(entry.getKey() + "," + sCpe);
					bf.newLine();
				}
				bf.flush();
			} catch (IOException e) {
				logger.error("ERROR: Failed to log CPE: {}", e.getMessage());
			}
		}
	}

}
