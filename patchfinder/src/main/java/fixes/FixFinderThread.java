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
import fixes.parsers.CISAParser;
import fixes.parsers.GenericParser;
import fixes.parsers.NVDParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

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
	private final List<String> urls;
	private List<Fix> fixes;

	// Get list of fixes
	public List<Fix> getFixes(){ return fixes; }

	/**
	 * Constructor for FixFinderThread. Takes in a CVE and a list of URLs
	 * to webpages which should be parsed for possible fixes for the vulnerability.
	 *
	 * @param cveId CVE to find fixes for
	 * @param urls Possible URLs to be scraped that may contain fixes
	 */
	public FixFinderThread(String cveId, List<String> urls){
		this.cveId = cveId;
		this.urls = urls;
	}

	@Override
	public void run() {
		// TODO: Create/finish parsers for web pages to find fix info. I already have the NVD one somewhat created for
		//  the vulnerability CVE-2022-2967 (see FixFinderMain), finish that or I will so that we can actually have our
		//  first working cve with a fix found.
		List<CompletableFuture<List<Fix>>> futures = new ArrayList<>();

		for (String url : urls) {
			CompletableFuture<List<Fix>> future = CompletableFuture.supplyAsync(() -> {

				FixParser parser = findCorrectParser(cveId, url);

				try{
					return parser.parseWebPage();
				} catch(IOException e){
					logger.error("Error occurred while parsing url {} for CVE {}", url, cveId);
					return null;
				}

			});

			futures.add(future);
		}

		// Wait for all futures to complete and collect their results
		List<Fix> allFixes = new ArrayList<>();
		for (CompletableFuture<List<Fix>> future : futures) {
			try {
				allFixes.addAll(future.get());
			} catch (InterruptedException | ExecutionException e) {
				// Handle exceptions as needed
				e.printStackTrace();
			}
		}

		// Add all fixes found to the static list defined in FixFinder
		try{
				FixFinder.getFixes().addAll(allFixes);
			} catch (IOException e){
				logger.error("Error occurred while parsing URL {} for CVE {}", url, cveId);
			}

		logger.info("{} fixes found for CVE {}", allFixes.size(), cveId);
	}

	/**
	 * Delegation method to determine which parser should be used to find fixes from the given url.
	 *
	 * @param cveId CVE ID for which fixes may be found
	 * @param url URL to page which will be parsed
	 * @return Correct parser to be used
	 *
	 * TODO: make this return more than just nvd/cisa etc, will come as we make more parsers
	 */
	public static FixParser findCorrectParser(String cveId, String url){
		FixParser parser;

		if(url.contains("nvd.nist.gov")) parser = new NVDParser(cveId, url);
		else if(url.contains("cisa.gov")) parser = new CISAParser(cveId, url);
		else parser = new GenericParser(cveId, url);

		return parser;
	}

}
