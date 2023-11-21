package patches; /**
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
import java.util.*;
import java.util.regex.Pattern;

/**
 * Responsible for finding possible patch source URLs for the PatchFinder
 *
 * @author Dylan Mulligan
 */
public class PatchUrlFinder {
	private static final Logger logger = LogManager.getLogger(PatchUrlFinder.class.getName());
	private static int advancedSearchCount;
	private static final ObjectMapper OM = new ObjectMapper();

	/**
	 * Parses possible patch URLs from all CPEs in the given affectedProducts map
	 * @param cveId id of Cve to parse urls for
	 * @param affectedProduct map of CVEs -> CPEs to parse source urls for
	 * @param cveLimit maximum number of CVEs to process
	 * @param isStale boolean representation of the quality of existing data in possiblePatchUrls
	 */
	public static List<String> parsePatchURLs(String cveId, CpeGroup affectedProduct, int cveLimit, boolean isStale) {
		final List<String> urls = new ArrayList<>();
		int cachedUrlCount = 0, foundCount = 0;
		final long entryStart = System.currentTimeMillis();

		// Warn and skip blank entries
		if(cveId.isEmpty() || affectedProduct.getVersionsCount() == 0) {
			logger.warn("Unable to parse URLs for empty affected product");
			return  urls;
		}

		try {
			// Find and store urls
			urls.addAll(parseURL(affectedProduct.getVendor(), affectedProduct.getProduct()));
			long entryDelta = (System.currentTimeMillis() - entryStart) / 1000;
			logger.info("Found {} potential patch sources for CVE '{}' in {} seconds", urls.size(), cveId, entryDelta);
			return urls;
		} catch (IOException e) {
			logger.error("Failed to parse urls from product {}: {}", affectedProduct.getProduct(), e);
		}
		logger.info("Found {} existing & fresh possible sources for {} CVEs, skipping url parsing...", foundCount, cachedUrlCount);
		return urls;
	}

	/**
	 * Parses URL with github.com base and cpe keywords tests connection and inserts
	 * into DB if so.
	 *
	 * @param product product name
	 * @param vendor vendor name
	 * @throws IOException if an IO error occurs while testing the url connection
	 */
	// TODO: Consider using https://www.cve.org to lookup existing github references to repos/PRs
	private static ArrayList<String> parseURL(String vendor, String product) throws IOException {
		ArrayList<String> newAddresses = new ArrayList<>();

		// Parse keywords from CPE to create links for GitHub, Bitbucket, and GitLab
		// Also checks if the created URL is already used
		if (!vendor.equals("*")) {
			HashSet<String> addresses = initializeAddresses(vendor);
			for (String address : addresses) {
				if (!product.equals("*")) {
					address += product;
				}

				// Check the HTTP connections for each URL,
				// If any successful, add them to the list to be stored
				ArrayList<String> connectedAddresses = testConnection(address);
				newAddresses.addAll(connectedAddresses);
			}
		} else if (!product.equals("*")) {
			for (String base : PatchFinder.addressBases) {
				String address = base + product;
				ArrayList<String> connectedAddresses = testConnection(address);
				newAddresses.addAll(connectedAddresses);
			}
		}

		// If no successful URLs, try an advanced search with
		// GitHub's search feature to double-check
		if (newAddresses.isEmpty()) {
			newAddresses = advanceParseSearch(vendor, product);
		}

		return newAddresses;
	}

	/**
	 * Initialize the address set with additional addresses based on cpe keywords
	 */
	private static HashSet<String> initializeAddresses(String keyword) {
		HashSet<String> addresses = new HashSet<>();

		for (String base : PatchFinder.addressBases) {
			addresses.add(base + keyword + "/");
		}

		return addresses;
	}

	/**
	 * Tests connection of a crafted URL, If successful, insert in DB else, search
	 * for correct repo via github company page (Assuming the link directs to it for
	 * now)
	 * 
	 * @param address address to test
	 * @return a list of valid addresses
	 * @throws IOException if an error occurs during the testing of the given address
	 */
	private static ArrayList<String> testConnection(String address) throws IOException {

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
	 * @param newURL url to search
	 */
	private static ArrayList<String> searchForRepos(String newURL) {
		logger.info("Grabbing repos from github user page...");

		ArrayList<String> urls = new ArrayList<>();

		// Obtain all links from the current company github page
		try {
			Document doc = Jsoup.connect(newURL).timeout(0).get();
			Elements links = doc.select("a[href]");
			// Loop through all links to find the repo page link (repo tab)
			for (Element link : links) {
				if (link.attr("href").contains("repositories")) {
					newURL = PatchFinder.addressBases[0] + link.attr("href").substring(1);
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
	 * @param repoLinks collection of page elements containing link data
	 * @return list of valid links only
	 */
	private static ArrayList<String> testLinks(Elements repoLinks) {
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
	 * @param product product name
	 * @param vendor vendor name
	 * @return a list of found links
	 */
	@SuppressWarnings({"unchecked", "rawtypes"})
	private static ArrayList<String> advanceParseSearch(String vendor, String product) {

		String searchParams = PatchFinder.addressBases[0] + "search?q=";
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
				if (advancedSearchCount >= 10) {
					logger.info("Performing Sleep before continuing: 1 minute");
					Thread.sleep(60000);
					advancedSearchCount = 0;
				}

				advancedSearchCount++;
				Document searchPage = Jsoup.connect(searchParams + "&type=repositories")
						.header("Accept-Encoding", "gzip, deflate")
						.userAgent("Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20100101 Firefox/23.0")
						.maxBodySize(0)
						.timeout(600000)
						.get();

				final LinkedHashMap searchData =
						(LinkedHashMap) OM.readValue(
								searchPage.select("div.application-main").select("script").get(0).html(),
								LinkedHashMap.class
						).get("payload");

				final ArrayList<LinkedHashMap> searchResults = (ArrayList<LinkedHashMap>) searchData.get("results");

				String newURL = null;
				for (LinkedHashMap searchResult : searchResults) {
					try {
						final String endpoint = ((String) searchResult.get("hl_name"))
								.replace("<em>", "")
								.replace("</em>", "");

						newURL = PatchFinder.addressBases[0] + endpoint;

						final String description = ((String) searchResult.get("hl_trunc_description"))
								.replace("<em>", "")
								.replace("</em>", "");


						if (verifyGitRemote(newURL, description, vendor, product)) {
							urls.add(newURL);
						}
					} catch (Exception e) {
						logger.warn("Failed to validate/verify URL {}: {}", newURL, e);
					}
				}
			} catch (IOException | InterruptedException e) {
				logger.error(e.toString());
				// If ratelimiting is detected, manually trigger sleep
				if(e.toString().contains("Status=429")) advancedSearchCount = 10;
			}

		return urls;
	}

	// TODO: What is the description param supposed to be filled by?
	/**
	 * Method used for verifying Git remote connection to created url via keywords,
	 * checks if the keywords are included as well before performing connection
	 *
	 * @param repoURL url to the repo to verify
	 * @param description url description
	 * @param vendor vendor name
	 * @param product product name
	 * @return result of verification
	 */
	private static boolean verifyGitRemote(String repoURL, String description, String vendor, String product) {

		// Verify if the repo is correlated to the product by checking if the keywords
		// lie in the inner text of the html link via regex
		if (Pattern.compile(Pattern.quote(vendor), Pattern.CASE_INSENSITIVE).matcher(description).find()
				|| Pattern.compile(Pattern.quote(product), Pattern.CASE_INSENSITIVE).matcher(description)
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
