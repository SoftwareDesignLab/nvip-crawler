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

import com.google.gson.JsonArray;
import edu.rit.se.nvip.cveprocess.CveProcessor;
import edu.rit.se.nvip.model.NvdVulnerability;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.UrlUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.json.Json;

/**
 * 
 * The main class for NVD feed reader
 * 
 * @author axoeec
 *
 */

public class NvdCveController {
	private final Logger logger = LogManager.getLogger(NvdCveController.class);

	private static final String nvdJsonFeedUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=<StartDate>&pubEndDate=<EndDate>";
	String[] header = new String[] { "CVE-ID", "Description", "BaseScore", "BaseSeverity", "ImpactScore", "ExploitabilityScore", "CWE", "Advisory", "Patch", "Exploit" };

	boolean logCPEInfo = true;

	private String startDate;
	private String endDate;

	/**
	 * for testing NVD CVE pull
	 * TODO: timeout exception when in middle of pulling NVD CVEs,
	 *  need to do latest to oldest in case this happens, or maybe just increase the sleeptime
	 * @param args
	 */
	public static void main(String[] args) {
		NvdCveController nvd = new NvdCveController();
		HashMap<String, NvdVulnerability> nvdCves = nvd.fetchNVDCVEs("https://services.nvd.nist.gov/rest/json/cves/2.0");
		for (String cve: nvdCves.keySet()) {
			System.out.println(nvdCves.get(cve));
		}
	}

	/**
	 * Constructor for NvdCveController
	 * Sets today and yesterday times on construction
	 */
	public NvdCveController() {
		LocalDateTime today = LocalDateTime.now();
		LocalDateTime lastMonth = LocalDateTime.now().minusDays(30);
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'hh:mm:ss");

		this.startDate = lastMonth.format(formatter);
		this.endDate = today.format(formatter);
	}

	/**
	 * For grabbing CVEs from NVD via NVD's API
	 * @param nvdApiPath
	 * @return
	 */
	public HashMap<String, NvdVulnerability> fetchNVDCVEs(String nvdApiPath) {
		HashMap<String, NvdVulnerability> NvdCves = new HashMap<>();
		int resultsPerPage = 2000;
		int startIndex = 0;
		int requestNum = 0;

		while (true) {
			// 30 second wait for eevry 5 requests, according to NVD Doc: https://nvd.nist.gov/developers/start-here
			if (requestNum >= 5) {
				logger.info("Sleeping for 60 seconds before continuing");
				try {
					Thread.sleep(60000);
					requestNum = 0;
				} catch (InterruptedException e) {
					logger.error("ERROR: Failed to wait 30seconds for pulling NVD CVEs\n{}", e);
				}
			}

			try {
				// Pull from NVD, keep track of startIndex for paginating response
				String url = nvdApiPath + "?resultsPerPage=" + resultsPerPage + "&startIndex=" + startIndex;
				URL apiUrl = new URL(url);
				HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
				connection.setRequestMethod("GET");

				if (connection.getResponseCode() != 200) {
					logger.error("Error retrieving CVEs: {}\n{}", connection.getResponseCode(), connection.getResponseMessage());
					break;
				}

				logger.info("Connection Acquired!");

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

				logger.info("Parsing CVEs");
				// for each vulnerability in response list, add cveId, publishedDate and status to the hashmap
				for (int i = 0; i < vulnerabilities.length(); i++) {
					JSONObject cve = vulnerabilities.getJSONObject(i);

					String cveId = cve.getJSONObject("cve").getString("id");
					String publishedDate = cve.getJSONObject("cve").getString("published");
					String status = cve.getJSONObject("cve").getString("vulnStatus");

//					logger.info("CVE ID: {}", cveId);
//					logger.info("Published Date: {}", publishedDate);
//					logger.info("Status: {}", status);

					NvdCves.put(cveId, new NvdVulnerability(cveId, publishedDate, status));
				}

				//logger.info("Pulled {} more CVEs from NVD", vulnerabilities.length());
				logger.info("{} Total CVEs", NvdCves.size());

				// Check if there's more CVEs to pull, otherwise break and return the data
				int totalResults = cveData.getInt("totalResults");
				startIndex += cveData.getInt("resultsPerPage");

				if (startIndex >= totalResults) {
					break;
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
	 * Main method of NVD_CVE_Reader
	 *
	 * @param filepath
	 */
	public int pullNvdCve(String filepath) {
		CsvUtils csvLogger = new CsvUtils(); // create output CSV file and append header

		// delete existing?
		File file = new File(filepath);
		boolean deleted = false;
		if (file.exists())
			deleted = file.delete();
		if (!deleted)
			logger.warn("Failed to delete existing file: {}", filepath);
		else
			logger.info("Deleted existing file: {}", filepath);

		logger.info("The output CSV will be at: {}", filepath);

		csvLogger.writeHeaderToCSV(filepath, header, false);

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

			// add references from this json list
//			nvdRefUrlHash.putAll(myCVEParser.getCveReferences(jsonList));

			// add references from this json list
//			nvdCveCpeHashMap.putAll(myCVEParser.getCPEs(jsonList));
		} catch (Exception e) {
			String url = nvdJsonFeedUrl.replaceAll("<StartDate>", this.startDate).replaceAll("<EndDate>", this.endDate);
			logger.error("ERROR: Failed to pull NVD CVES for year {}, url: {}\n{}", this.startDate, url, e.getMessage());
		}

		logger.info("Wrote a total of *** {} *** entries to CSV file: {}", totCount, filepath);

		// process&store references
		processCVEReferences(nvdRefUrlHash, filepath);

		logCPEInfo(filepath, nvdCveCpeHashMap);

		return totCount;
	}

	/**
	 * Process Nvd reference URLs
	 *
	 * @param nvdRefUrlHash
	 * @param filepath
	 */
	private void processCVEReferences(Map<String, Integer> nvdRefUrlHash, String filepath) {
		UrlUtils urlUtils = new UrlUtils();
		int count = 0;
		Map<String, Integer> nvdBaseRefUrlHash = new HashMap<>();
		List<String> listFullRefUrls = new ArrayList<>();
		try {
			for (String sUrl : nvdRefUrlHash.keySet()) {
				String sBaseUrl = urlUtils.getBaseUrl(sUrl);
				if (sBaseUrl != null) {
					listFullRefUrls.add(sUrl);
					nvdBaseRefUrlHash.put(sBaseUrl, 0);
				}

				count++;
				if (count % 10000 == 0)
					logger.info("Processed {} URLs...", count);

			}

			List<String> listBaseRefUrls = new ArrayList<>();
			listBaseRefUrls.addAll(nvdBaseRefUrlHash.keySet());

			filepath = filepath.replace(".csv", "");
			filepath = filepath.substring(0, filepath.lastIndexOf("/")) + "/url-sources/";
			String sFullReferencePath = filepath + "nvd-cve-full-references.csv";
			String sBaseReferencePath = filepath + "nvd-cve-base-references.csv";
			FileUtils.writeLines(new File(sFullReferencePath), listFullRefUrls, false);
			FileUtils.writeLines(new File(sBaseReferencePath), listBaseRefUrls, false);

			int totInvalid = nvdRefUrlHash.keySet().size() - listFullRefUrls.size();
			logger.info("\nScraped {} total NVD full-reference URLs.\nThe # of invalid full-references: {}\nThe # of recorded full-references: {}" +
							"\nTotal # of unique base URLs: {}\nReference URLs are stored at: {} and {}",
					count, totInvalid, listFullRefUrls.size(), nvdBaseRefUrlHash.keySet().size(), sFullReferencePath, sBaseReferencePath);
		} catch (IOException e) {
			logger.error("Error while processing NVD references!\n{}", e.getMessage());
		}
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
