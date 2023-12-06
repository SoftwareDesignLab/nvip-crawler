/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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

import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

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
			String[] items = getCveID(json);
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
	private String[] getCveID(JsonObject json) {
		String[] items = new String[2];

		try {
			if (json.getAsJsonObject("cveMetaData") != null) {
				items[0] = json.getAsJsonObject("cveMetaData").get("cveId").getAsString();
				items[1] = json.getAsJsonObject("cveMetaData").get("state").getAsString();
			} else {
				items[0] = json.getAsJsonObject("CVE_data_meta").get("ID").getAsString();
				items[1] = json.getAsJsonObject("CVE_data_meta").get("STATE").getAsString();
			}

		} catch (Exception e) {
			logger.error("Error parsing json: {}. {}", json, e.toString());
		}

		return items;

	}

}
