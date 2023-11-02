package fixes.urlfinders;

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

import fixes.FixProcessor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Abstract class responsible for finding possible fix source URLs for the FixFinder.
 *
 * @author Dylan Mulligan
 */

public abstract class FixUrlFinder extends FixProcessor {
	// To be implemented in child classes, houses the actual logic that selects source urls
	public abstract List<String> getUrls(String cveId) throws IOException;

	//Called for all child instances, makes use of their specific implementation of
	// getUrls(), then tests and filters out any urls that can't be connected to
	public List<String> run(String cveId) {
		try {
			final List<String> urls = this.getUrls(cveId);
			// Test each source for a valid connection and filter failed connections
			return urls.stream().filter(FixUrlFinder::testConnection).toList();
		} catch (IOException e) {
			logger.error("Failed to get urls for CVE '{}': {}", cveId, e.toString());
			return new ArrayList<>();
		}
	}

	// Tests the connection of a given address and returns the boolean result of the test
	protected static boolean testConnection(String address) {
		logger.info("Testing Connection for address: " + address);

		try {
			URL url = new URL(address);
			HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
			final int response = urlConnection.getResponseCode();
			// Don't print OK responses, only when this is not the case
			if(response != 200) logger.info("Response Code: " + response);
			return true;
		} catch (Exception e) {
			logger.error("ERROR: Failed to connect to {}\n{}", address, e);
			return false;
		}
	}

}
