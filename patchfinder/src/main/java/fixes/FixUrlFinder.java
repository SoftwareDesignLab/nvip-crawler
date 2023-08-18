package fixes; /**
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

import com.fasterxml.jackson.databind.ObjectMapper;
import env.FixFinderEnvVars;
import env.PatchFinderEnvVars;
import model.CpeGroup;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.LsRemoteCommand;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import db.DatabaseHelper;

/**
 * Responsible for finding possible patch source URLs for the FixFinder
 *
 * @author Dylan Mulligan
 */
// TODO: Make this an abstract class, to be extended/implemented to source data from a specific source
// TODO: Implement VulnerabilityFixUrlFinder & NvdFixUrlFinder
public class FixUrlFinder {
	private static final Logger logger = LogManager.getLogger(FixUrlFinder.class.getName());
//	private static final ObjectMapper OM = new ObjectMapper();
	private static DatabaseHelper databaseHelper;

	// TODO: Implement testConnection method to validate all urls can connect
	private static boolean testConnection(String address) throws IOException {
		logger.info("Testing Connection for address: " + address);
		ArrayList<String> urlList = new ArrayList<>();

		URL url = new URL(address);
		HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
		int response;

		try {
			response = urlConnection.getResponseCode();
			logger.info("Response Code: " + response);
			return true;
		} catch (Exception e) {
			logger.error("ERROR: Failed to connect to {}\n{}", address, e);
			response = -1;
			return false;
		}
	}


	//TODO: Move to its own implementation (maybe VulnerabilityFixUrlFinder)
	public ArrayList<String> run(String cveId) throws IOException {
		logger.info("Getting Fix URLs for CVE: " + cveId);
		ArrayList<String> urlList = new ArrayList<>();

		// Get all sources for the CVE
		ArrayList<String> sources = databaseHelper.getCveSources(cveId);

		// Test each source for a valid connection
		for (String source : sources) {
			if (testConnection(source)) {
				urlList.add(source);
			}
		}

		return urlList;
	}
}
