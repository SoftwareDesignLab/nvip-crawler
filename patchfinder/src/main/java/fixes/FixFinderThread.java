package fixes;

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

import fixes.parsers.FixParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.Set;

/**
 * Runnable thread class for multithreaded FixFinder. Used for finding fixes for CVEs from sources.
 *
 * @author Dylan Mulligan
 * @author Paul Vickers
 *
 * TODO: make it use futures or whatever
 */
public class FixFinderThread implements Runnable {
	private static final Logger logger = LogManager.getLogger(FixFinder.class.getName());
	private final String cveId;
	private final String url;
	private Set<Fix> fixes;

	// Get list of fixes
	public Set<Fix> getFixes(){ return this.fixes; }

	/**
	 * Constructor for FixFinderThread. Takes in a CVE and a list of URLs
	 * to webpages which should be parsed for possible fixes for the vulnerability.
	 *
	 * @param cveId CVE to find fixes for
	 * @param url Possible URL to be scraped that may contain fixes
	 */
	public FixFinderThread(String cveId, String url){
		this.cveId = cveId;
		this.url = url;
	}

	/**
	 * Run method used to iterate through all the possible fix URLs for the CVE.
	 *
	 * Delegates each URL to its own specific parser or generic parser if no specific one has
	 * been created for it (yet).
	 *
	 * For each URL, uses the parser to extract fixes and stores them in the static list from FixFinder class.
	 */
	@Override
	public void run() {
		try{
			this.fixes = FixParser.getParser(cveId, url).parse();
		} catch(IOException e){
			logger.error("Error occurred while parsing url {} for CVE {}: {}", url, cveId, e.toString());
			e.printStackTrace();
		}
	}

}
