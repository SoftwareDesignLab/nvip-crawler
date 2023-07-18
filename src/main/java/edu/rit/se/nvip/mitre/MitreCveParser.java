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
package edu.rit.se.nvip.mitre;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * 
 * Mitre CVE parser
 * Used for grabbing CVEs that are stored in CVE.mitre
 * 
 * @author axoeec
 *
 */
public class MitreCveParser {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	/**
	 * parse JSON items from CVE MITRE repo
	 * 
	 * @param list
	 * @return
	 */
	public List<String[]> parseCVEJSONFiles(ArrayList<JsonObject> list) {
		List<String[]> cveIDList = new ArrayList<>();
		for (JsonObject json : list) {
			String[] items = getCVEID(json);
			if (items != null)
				cveIDList.add(items);
		}

		return cveIDList;
	}

	/**
	 * parse one MITRE CVE JSON from CVE MITRE repo
	 * 
	 * @param json
	 * @return
	 */
	private String[] getCVEID(JsonObject json) {
		String[] items = new String[4];

		try {
			if (json.getAsJsonArray("cveMetaData") != null) {
				items[0] = json.getAsJsonObject("cveMetadata").get("cveId").toString().replace("\"", "");
				items[1] = json.getAsJsonObject("cveMetadata").get("state").toString();
				items[2] = json.getAsJsonObject("cveMetadata").get("datePublished").toString();
				items[3] = json.getAsJsonObject("cveMetadata").get("dateUpdated").toString();
			} else {
				items[0] = json.getAsJsonObject("CVE_data_meta").get("ID").toString().replace("\"", "");
				items[1] = json.getAsJsonObject("CVE_data_meta").get("STATE").toString();
				items[2] = "";
				items[3] = "";
			}

		} catch (Exception e) {
			logger.error("Error parsing json: {}. {}", json, e.toString());
		}

		return items;

	}

}
