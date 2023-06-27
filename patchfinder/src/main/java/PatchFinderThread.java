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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import commits.PatchCommit;
import commits.PatchCommitScraper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import utils.GitController;

import static org.apache.commons.lang3.time.DateUtils.parseDate;

/**
 * Runnable thread class for multithreaded patch finder
 *
 * Used for finding patches from sources defined in a provided list
 *
 * @author Dylan Mulligan
 */
public class PatchFinderThread implements Runnable {
	private final HashMap<String, ArrayList<String>> cvePatchEntry;
	private final String clonePath;
	private final long timeoutMilli;
	// Regex101: https://regex101.com/r/YiCdNU/1
	private final static Pattern commitPattern = Pattern.compile("commit-details-(\\w*)");
	private static final Pattern[] patchPatterns = new Pattern[] {Pattern.compile("vulnerability|Vulnerability|vuln|Vuln|VULN[ #]*([0-9]+)")};
	private static final Logger logger = LogManager.getLogger(PatchFinder.class.getName());

	/**
	 * Thread object used for multithreaded patchfinding
	 * @param cvePatchEntry
	 */
	public PatchFinderThread(HashMap<String, ArrayList<String>> cvePatchEntry, String clonePath, long timeoutMilli) {
		this.cvePatchEntry = cvePatchEntry;
		this.clonePath = clonePath;
		this.timeoutMilli = timeoutMilli;
	}

	/**
	 * Used for cloning, crawling, and deleting product repos to find patch commits
	 */
	@Override
	public void run() {
		final long totalStart = System.currentTimeMillis();

		ArrayList<PatchCommit> foundPatchCommits = new ArrayList<>();
		// For each CVE, iterate through the list of possible patch sources and
		// Clone/Scrape the repo for patch commits (if any)
		for (String cve : cvePatchEntry.keySet()) {
			for (String patchSource: cvePatchEntry.get(cve)) {
				findPatchCommits(foundPatchCommits, cve, patchSource);
			}
		}

		// Add found commits to total list after finished
		PatchFinder.getPatchCommits().addAll(foundPatchCommits);

		final long delta = (System.currentTimeMillis() - totalStart) / 1000;
		logger.info("Done scraping {} patch commits from CVE(s) {} in {} seconds", foundPatchCommits.size(), cvePatchEntry.keySet(), delta);
	}

	private void findPatchCommits(ArrayList<PatchCommit> foundPatchCommits, String cve, String patchSource) {
		try {
			final long connStart = System.nanoTime();

			// Build connection object and execute connection operation
			final Connection conn = Jsoup.connect(patchSource).timeout((int) this.timeoutMilli);
			conn.execute();

			// Get response
			final Connection.Response response = conn.response();

			// Get response code
			final int responseCode = response.statusCode();

			// Only allow valid responses
			if(responseCode >= 200 && responseCode < 300) {
				// Log connection stats
				logger.info("Connection to URL '{}' successful. Done in {} ms",
						patchSource,
						(int) ((System.nanoTime() - connStart) / 1000000)
				);

				// Get page body as DOM
				final Document DOM = Jsoup.parse(response.body());

				// Get commit count element
				final Element commitCountElement = DOM.select("div > div.js-details-container").select("strong").first();

				// Throw exception if no elements found
				if(commitCountElement == null) throw new IllegalArgumentException("Failed to find commit count page element");

				// Extract commit count value and throw specific exception if this fails
				final int commitCount;
				try {
					commitCount = Integer.parseInt(commitCountElement.text().replace(",", ""));
				} catch (NumberFormatException ignored) {
					throw new IOException("Failed to extract commit count from URL " + patchSource);
				}
				logger.info("Found {} commits on the master branch @ URL '{}'", commitCount, patchSource);

				// If commit count is under threshold, scrape commits from url
				if(commitCount <= PatchFinder.maxCommits) {
					findPatchCommitsFromUrl(foundPatchCommits, cve, patchSource, commitCount);
				} else { // Otherwise, clone repo to parse commits
					findPatchCommitsFromRepo(foundPatchCommits, cve, patchSource);
				}

			} else throw new IllegalArgumentException("Received invalid response code " + responseCode);

		} catch (Exception e) {
			logger.error("Failed to find patch from source {} for CVE {}: {}", patchSource, cve, e.toString());
		}
	}

	private void findPatchCommitsFromUrl(ArrayList<PatchCommit> foundPatchCommits, String cve, String patchSource, int commitCount) {
		// Define page range
		final int numPags = (int) Math.ceil((double) commitCount / 35);
		final String baseCommitsUrl = patchSource + "/commits";

		// Query first page and get HEAD commit
		try {
			// TODO: Paginate
			final Elements firstPageCommitObjects = getCommitObjects(baseCommitsUrl);

			// Ensure at least one commit was found
			if(firstPageCommitObjects.size() == 0) throw new IOException("Failed to extract commits from page data");

			// Extract the head commit SHA for pagination
			final String[] headCommitParts = firstPageCommitObjects.first().attr("href").split("/");
			final String headCommitEndpoint = "?after=" + headCommitParts[headCommitParts.length - 1];

			// Parse first page objects
			parseCommitObjects(foundPatchCommits, cve, firstPageCommitObjects);

			// Generate list of page urls to query with head commit SHA
			final List<String> pageUrls = new ArrayList<>();
			for (int i = 35; i < numPags * 35; i += 35) pageUrls.add(baseCommitsUrl + headCommitEndpoint + "+" + i);

			for (String url : pageUrls) {
				// Extract commit objects from url
				final Elements commitObjects = getCommitObjects(url);

				// Ensure at least one object was found
				if(commitObjects.size() == 0) {
					logger.warn("Failed to find commit objects from url '{}'", url);
					continue;
				}

				// Iterate over found commitObjects, then build and store ParseCommit objects
				parseCommitObjects(foundPatchCommits, cve, commitObjects);
			}

		} catch (IOException e) {
			logger.error("Failed to find patch commits from URL '{}': {}", patchSource, e);
		}
	}

	private void findPatchCommitsFromRepo(ArrayList<PatchCommit> foundPatchCommits, String cve, String patchSource) {
		try {
			// Clone git repo
			String localDownloadLoc = clonePath + "/" + cve + "-" + patchSource.substring(patchSource.lastIndexOf("/") + 1);

			GitController gitController = new GitController(
					localDownloadLoc,
					patchSource+".git"
			);
			gitController.cloneRepo();

			// Find patch commits
			PatchCommitScraper commitScraper = new PatchCommitScraper(
					localDownloadLoc,
					patchSource
			);
			List<PatchCommit> patchCommits = commitScraper.parseCommits(cve, patchPatterns);
			foundPatchCommits.addAll(patchCommits);

//					// Delete repo when done
//					gitController.deleteRepo();
		} catch (Exception e) {
			logger.error("ERROR: Failed to find patch from source {} for CVE {}\n{}", patchSource, cve, e.toString());
			e.printStackTrace();
		}
	}

	// TODO: Parse raw data into PatchCommit objects
	private void parseCommitObjects(List<PatchCommit> patchCommits, String cveId, Elements objects) {
		// Check if the commit message matches any of the regex provided
		for (Pattern pattern : patchPatterns) {
			for (Element object : objects) {
				Matcher matcher = pattern.matcher(object.text());
				// If found the CVE ID is found, add the patch commit to the returned list
				if (matcher.find() || object.text().contains(cveId)) {
					String commitUrl = object.attr("href");
					logger.info("Found patch commit @ URL '{}'", commitUrl);
//					String unifiedDiff = generateUnifiedDiff(git, commit);

					PatchCommit patchCommit = new PatchCommit(
							commitUrl,
							cveId,
							object.text(),
							new Date(object.attr("commitTime")),
							object.text(),
							null, // unifiedDiff
							null,
							null,
							0
							);

					patchCommits.add(patchCommit);
				}
			}
		}
	}

	private Elements getCommitObjects(String url) {
		// Init output Elements list
		final Elements commitObjects = new Elements();

		try {
			// Get DOM and extract commit message container elements
			final Document DOM = Jsoup.connect(url).get();


			// Extract raw message containers
			final Elements commitElements = DOM.select("div.TimelineItem").select("li");
			final Elements messageContainers = commitElements.select("div.js-details-container");
			final Elements dateElements = commitElements.select("relative-time");

			// Iterate over found message containers
			for (int i = 0, stop = messageContainers.size(); i < stop; i++) {
				final Element container = messageContainers.get(i);

				//TODO: Include "pre" tagged elements (full commit message descriptions).
				// Store commit message and commit description separately, using commit message as the
				// description in the case that there is no description

				// Select message element(s) (will be length 1 a lot)
				final Elements messageElements = container.select("a").not("a.commit-author,a.avatar");

				// Get the first message element
				final Element messageElement = messageElements.first();

				// Append date information
				messageElement.attr("commitTime", dateElements.get(i).attr("datetime"));

				// If not length 1, message is split into multiple parts and must be combined
				if (messageElements.size() > 1) {

					// Build the full message
					final String message = String.join("", messageElements
							.stream().map(me -> {
								final String text = me.text();
								if (text.startsWith("...")) return text.substring(3);
								else if (text.endsWith("...")) return text.substring(0, text.length() - 3);
								else return text;
							}).toArray(String[]::new));

					// Set the first element's text to the combined message
					messageElement.html(message);
				}

				// Add element to commit objects
				commitObjects.add(messageElement);
			}
		} catch (IOException e) {
			logger.error("Failed to extract commit objects from URL '{}': {}", url, e);
		}

		// Return collected commit objects
		return commitObjects;
	}
}
