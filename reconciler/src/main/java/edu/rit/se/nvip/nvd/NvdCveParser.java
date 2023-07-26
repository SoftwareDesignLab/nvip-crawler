/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.nvd;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.*;

/**
 * 
 * NvdCveParser class parses Common Vulnerabilities and Exposures (CVE) from the
 * National Vulnerability Database (NVD).
 * 
 * @author axoeec
 *
 */
public class NvdCveParser {

	public NvdCveParser() {
	}

	/**
	 * Parse all CVEs for a given year
	 * 
	 * @param jsonList <year> as a 4 digit int
	 * @return list of CVE IDs and Descriptions
	 */
	public List<String[]> parseCVEs(JsonArray jsonList) {
		List<String[]> allData = new ArrayList<>();
		// parse all CVEs in all JSONs (if multiple)
		for (JsonElement json : jsonList) {

			// { id, sourceIdentifier, published, lastModified, vulnStatus, descriptions, metrics, weaknesses, references }
			JsonObject cve = (JsonObject) json;
			cve = cve.getAsJsonObject("cve");
			String cveId = cve.get("id").getAsString();
			// descriptions -> [ { lang, value } ]
			JsonArray descriptions = cve.getAsJsonArray("descriptions");
			String description = descriptions.get(0).getAsJsonObject().get("value").getAsString().replace("\n", "");

			String publishDate = cve.get("published").getAsString();
			String lastModifiedDate = cve.get("lastModified").getAsString();

			// metrics -> cvssMetricV31 -> [ { cvssData { 12 } } ]
			JsonObject metrics = cve.getAsJsonObject("metrics");
			String impactScore = "";
			String exploitabilityScore = "";
			String baseScore = "";
			String baseSeverity = "";
			if (!metrics.isJsonNull() && !metrics.entrySet().isEmpty()) {
				JsonElement metric = metrics.get("cvssMetricV31");
				JsonObject cvssMetrics;
				if (metric == null)
					metric = metrics.get("cvssMetricV30");
				if (metric != null) {
					cvssMetrics = metric.getAsJsonArray().get(0).getAsJsonObject();
					if (!cvssMetrics.isJsonNull() && !cvssMetrics.entrySet().isEmpty()) {
						impactScore = cvssMetrics.get("impactScore").getAsString();
						exploitabilityScore = cvssMetrics.get("exploitabilityScore").getAsString();
						JsonObject cvssData = cvssMetrics.getAsJsonObject("cvssData");
						if (!cvssData.isJsonNull() && !cvssData.entrySet().isEmpty()) {
							baseScore = cvssData.get("baseScore").getAsString();
							baseSeverity = cvssData.get("baseSeverity").getAsString();
						}
					}
				}
			}
			String cwe = "";
			JsonArray weaknesses = cve.getAsJsonArray("weaknesses");
			if (weaknesses != null && weaknesses.size() != 0) {
				cwe = weaknesses.get(0).getAsJsonObject().get("description").getAsJsonArray().get(0).getAsJsonObject().get("value").getAsString();
			}

			// nothing regarding Advisory, Patch, Exploit in JSON response
			// those will be left as empty strings
			allData.add(new String[]{cveId, description, publishDate, lastModifiedDate, baseScore, baseSeverity, impactScore, exploitabilityScore, cwe, "", "", ""});
		}

		return allData;
	}

	/**
	 * get CVE references from json list
	 * 
	 * @param jsonList
	 * @return
	 */
	public Map<String, Integer> getCveReferences(ArrayList<JsonObject> jsonList) {
		Map<String, Integer> refUrlHash = new HashMap<>();

		for (JsonObject json : jsonList) {
			JsonArray items = json.getAsJsonArray("CVE_Items");
			Iterator<JsonElement> iterator = items.iterator();
			while (iterator.hasNext()) {
				try {
					JsonObject jsonCVE = (JsonObject) iterator.next();
					JsonObject jsonObj = jsonCVE.getAsJsonObject("cve");

					JsonArray jsonArray = jsonObj.getAsJsonObject("references").getAsJsonArray("reference_data");
					for (JsonElement element : jsonArray) {
						String sUrl = element.getAsJsonObject().get("url").getAsString();
						refUrlHash.put(sUrl, 0);
					}
				} catch (Exception ignored) {
				}
			}
		}

		return refUrlHash;
	}

}
