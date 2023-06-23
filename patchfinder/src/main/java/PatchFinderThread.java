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
		logger.info("Done scraping {} patch commits from CVE(s) [{}] in {} seconds", foundPatchCommits.size(), cvePatchEntry.keySet(), delta);
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

				// Find commit count container
				final Elements elements = DOM.select("div > div.js-details-container").select("span.d-none");

				// Throw exception if no elements found
				if(elements.size() == 0) throw new IllegalArgumentException("Failed to find commit count page element");

				// Get commit count element
				final Element commitCountContainer = elements.get(0);
				final Element commitCountElement = commitCountContainer.child(0);
				final int commitCount = Integer.parseInt(commitCountElement.text());
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
			// Get DOM and extract commit message container elements
			final Document DOM = Jsoup.connect(baseCommitsUrl).get();

			// Get commit html objects from page
			final Elements commitObjects = getCommitObjects(DOM);

			// Ensure at least one commit was found
			if(commitObjects.size() == 0) throw new IOException("Failed to extract commits from page data");

			// Extract the head commit SHA for pagination
			final String[] headCommitParts = commitObjects.first().attr("href").split("/");
			final String headCommitEndpoint = "?after=" + headCommitParts[headCommitParts.length - 1];

			// Generate list of page urls to query with head commit SHA
			final List<String> pageUrls = new ArrayList<>();
			for (int i = 0; i < numPags * 35; i += 35) pageUrls.add(baseCommitsUrl + headCommitEndpoint + "+" + i);

//			// Extract commit messages and parse into patch commits
//			final StringBuilder sb = new StringBuilder();
//			for (final Element e : messageContainers) {
//				final Elements messageParts = e.select("p");
//
//				int count = 0;
//				for (Element part : messageParts) {
//					final String partString = part.text();
//					count++;
//					// If multipart message, truncate trailing and leading "..."
//					if(count > 1) {
//						sb.setLength(sb.length() - 3);
//						sb.append(partString, 0, partString.length() - 3);
//					} else sb.append(partString);
//				}
//
//				foundPatchCommits.add(parseCommitMessage(cve, sb.toString()));
//				sb.setLength(0);
//			}
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

	private PatchCommit parseCommitMessage(String cveId, String messageContents) {
		return null;
	}

	private Elements getCommitObjects(Document DOM) {
		final Elements commitObjects = new Elements();

		final Elements commitElements = DOM.select("div.TimelineItem").select("li");
		final Elements messageContainers = commitElements.select("div.js-details-container");
		for (Element e : messageContainers) {
			final Elements messageElements = e.select("a").not("a.commit-author,a.avatar");
			if(messageElements.size() > 1) {
				// TODO: Handle split messages
			} else commitObjects.add(e);
		}
		return commitObjects;
	}
}
