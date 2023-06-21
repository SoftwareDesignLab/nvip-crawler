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

import db.DatabaseHelper;
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
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Start patch finder for a given repository list (as .csv)
 *
 * Responsible for finding possible patch source URLs
 */
public class PatchUrlFinder {

	private static final Logger logger = LogManager.getLogger(PatchUrlFinder.class.getName());
	// TODO: add to envvars?
	private static final String[] ADDRESS_BASES = { "https://www.github.com/", "https://www.gitlab.com/" };

	// TODO: all old vars, get rid of these
	private static int advanceSearchCount;

	/**
	 * Parse URLs from all CPEs given within the map
	 * @param affectedProducts
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public Map<String, ArrayList<String>> parseMassURLs(Map<String, CpeGroup> affectedProducts, int cveLimit) throws IOException, InterruptedException {
		Map<String, ArrayList<String>> cveCpeUrls = new HashMap<>();

		final long totalStart = System.currentTimeMillis();
		for (Map.Entry<String, CpeGroup> entry : affectedProducts.entrySet()) {
			final long entryStart = System.currentTimeMillis();
			final String cveId = entry.getKey();
			final CpeGroup group = entry.getValue();
			// Break out of loop when limit is reached
			if (cveCpeUrls.size() >= cveLimit) {
				logger.info("CVE limit of {} reached for patchfinder", cveLimit);
				break;
			}

			// Find urls
			final ArrayList<String> urls = parseURL(group.getVendor(), group.getProduct());

			// Store found urls
			cveCpeUrls.put(cveId, urls);
			long entryDelta = (System.currentTimeMillis() - entryStart) / 1000;
			logger.info("Found {} potential patch sources for CVE '{}' in {} seconds", urls.size(), cveId, entryDelta);
		}

		long totalDelta = (System.currentTimeMillis() - totalStart) / 1000;
		logger.info("Found {} potential patch sources for {} CVEs in {} seconds", cveCpeUrls.size(), Math.min(cveLimit, affectedProducts.size()), totalDelta);
		return cveCpeUrls;
	}

	/**
	 * Parses URL with github.com base and cpe keywords tests connection and inserts
	 * into DB if so.
	 *
	 * @throws IOException
	 * @throws InterruptedException
	 */
	private ArrayList<String> parseURL(String vendor, String product) throws IOException, InterruptedException {
		ArrayList<String> newAddresses = new ArrayList<>();
		
		// TODO: Fix this
		// Parse keywords from CPE to create links for github, bitbucket and gitlab
		// Also checks if the created URL is already used
		if (!vendor.equals("*")) {
			HashSet<String> addresses = initializeAddresses(vendor);
			for (String address : addresses) {
				if (!product.equals("*")) {
					address += product;
				}

				// Check the http connections for each URL,
				// If any successful, add them to the list to be stored
				newAddresses = testConnection(address);
			}

		} else if (!product.equals("*")) {
			for (String base : ADDRESS_BASES) {
				String address = base + product;
				newAddresses = testConnection(address);
			}
		}

		// If no successful URLs, try an advanced search with
		// GitHub's search feature to double check
		if (newAddresses.isEmpty()) {
			newAddresses = advanceParseSearch(vendor, product);
		}

		return newAddresses;
		
	}

	/**
	 * Initialize the address set with additional addresses based on cpe keywords
	 */
	private HashSet<String> initializeAddresses(String keyword) {
		HashSet<String> addresses = new HashSet<>();

		for (String base : ADDRESS_BASES) {
			addresses.add(base + keyword + "/");
		}

		return addresses;
	}

	/**
	 * Tests connection of a crafted URL, If successful, insert in DB else, search
	 * for correct repo via github company page (Assuming the link directs to it for
	 * now)
	 * 
	 * @param address
	 * @return
	 * @throws IOException
	 */
	private ArrayList<String> testConnection(String address) throws IOException {

		logger.info("Testing Connection for address: " + address);
		ArrayList<String> urlList = new ArrayList<>();

		URL url = new URL(address);
		HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
		int response;

		try {
			response = urlConnection.getResponseCode();
		} catch (Exception e) {
			logger.error("ERROR: Failed to connect to {}\n{}", address, e);
			response = -1;
		}


		// Check if the url leads to an actual GitHub repo
		// If so, push the source link into the DB
		if (response >= 200 && response < 300) {
			urlConnection.connect();

			// Get correct URL in case of redirection
			InputStream is = urlConnection.getInputStream();
			String newURL = urlConnection.getURL().toString();

			urlConnection.disconnect();
			is.close();

			LsRemoteCommand lsCmd = new LsRemoteCommand(null);

			lsCmd.setRemote(newURL + ".git");

			try {
				lsCmd.call();
				logger.info("Successful Git Remote Connection at: " + newURL);
				urlList.add(newURL);
			} catch (Exception e) {
				// If unsuccessful on git remote check, perform an advanced search, assuming the
				// link instead leads to a github company home page
				logger.error(e.getMessage());
				return searchForRepos(newURL);
			}

		}
		return urlList;
	}

	/**
	 * Searches for all links within a companies github page to find the correct
	 * repo the cpe is correlated to. Uses keywords from cpe to validate and checks
	 * for git remote connection with found links
	 * 
	 * Uses jSoup framework
	 *
	 * @param newURL
	 */
	private ArrayList<String> searchForRepos(String newURL) {
		logger.info("Grabbing repos from github user page...");

		ArrayList<String> urls = new ArrayList<>();

		// Obtain all links from the current company github page
		try {
			Document doc = Jsoup.connect(newURL).timeout(0).get();
			Elements links = doc.select("a[href]");
			// Loop through all links to find the repo page link (repo tab)
			for (Element link : links) {
				if (link.attr("href").contains("repositories")) {
					newURL = ADDRESS_BASES[0] + link.attr("href").substring(1);
					Document reposPage = Jsoup.connect(newURL).timeout(0).get();
					Elements repoLinks = reposPage.select("li.Box-row a.d-inline-block[href]");

					// Loop through all repo links in the repo tab page and test for git clone
					// verification. Return the list of all successful links afterwards
					urls = testLinks(repoLinks);

					// Check if the list is empty, if so it could be because the wrong html element
					// was pulled for repoLinks. In this case, try again with a different element
					// assuming the link redirects to a github profile page instead of a company
					// page
					if (urls.isEmpty()) {
						repoLinks = reposPage.select("div.d-inline-block a[href]");
						urls = testLinks(repoLinks);
					}
				}
			}
		} catch (IOException e) {
			logger.error(e.getMessage());
		}

		return urls;

	}

	/**
	 * Method to loop through given repo links and verify git connection, returns
	 * list of all successful links
	 * 
	 * @return
	 */
	private ArrayList<String> testLinks(Elements repoLinks) {
		ArrayList<String> urls = new ArrayList<>();
		String repoURL;

		for (Element repoLink : repoLinks) {
			logger.info("Found possible repo at:" + repoLink.attr("abs:href"));
			repoURL = repoLink.attr("abs:href");
			String innerText = repoLink.text();

			if (verifyGitRemote(repoURL, innerText, "", "")) {
				urls.add(repoURL);
			}
		}

		return urls;
	}

	/**
	 * Performs an advanced search for the repo link(s) for a CPE using the Github
	 * search feature
	 *
	 * @return
	 * @throws InterruptedException
	 */
	private ArrayList<String> advanceParseSearch(String vendor, String product) throws InterruptedException {

		String searchParams = ADDRESS_BASES[0] + "search?q=";
		ArrayList<String> urls = new ArrayList<>();

			logger.info("Conducting Advanced Search...");

			if (!vendor.equals("*")) {
				searchParams += vendor;
			}

			if (!product.equals("*")) {
				searchParams += "+" + product;
			}

			// Perform search on github using query strings in the url
			// Loop through the results and return a list of all verified repo links that
			// match with the product
			try {
				// Sleep for a minute before performing another advance search if
				// 10 have already been conducted to avoid HTTP 429 error
				if (advanceSearchCount >= 10) {
					logger.info("Performing Sleep before continuing: 1 minute");
					Thread.sleep(60000);
					advanceSearchCount = 0;
				}

				advanceSearchCount++;
				Document searchPage = Jsoup.connect(searchParams + "&type=repositories").get();
				Elements searchResults = searchPage.select("li.repo-list-item a[href]");

				for (Element searchResult : searchResults) {
					if (!searchResult.attr("href").isEmpty()) {
						String newURL = searchResult.attr("abs:href");
						String innerText = searchResult.text();
						if (verifyGitRemote(newURL, innerText, vendor, product)) {
							urls.add(newURL);
						}
					}
				}

			} catch (IOException e) {
				logger.error(e.toString());
			}

		return urls;
	}

	/**
	 * Method used for verifying Git remote connection to created url via keywords,
	 * checks if the keywords are included as well before performing connection
	 * @return
	 */
	private boolean verifyGitRemote(String repoURL, String innerText, String vendor, String product) {

		// Verify if the repo is correlated to the product by checking if the keywords
		// lie in the inner text of the html link via regex
		if (Pattern.compile(Pattern.quote(vendor), Pattern.CASE_INSENSITIVE).matcher(innerText).find()
				|| Pattern.compile(Pattern.quote(product), Pattern.CASE_INSENSITIVE).matcher(innerText)
						.find()) {

			LsRemoteCommand lsCmd = new LsRemoteCommand(null);

			lsCmd.setRemote(repoURL + ".git");

			try {
				lsCmd.call();
				logger.info("Successful Git Remote Connection at: " + repoURL);
				return true;
			} catch (Exception e) {
				logger.error(e.getMessage());
			}
		}
		return false;
	}


}
