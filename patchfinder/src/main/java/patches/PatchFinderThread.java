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

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import env.PatchFinderEnvVars;
import patches.PatchCommit;
import patches.PatchCommitScraper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.revwalk.RevWalk;
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
	private RevWalk walk; // TODO: initialize properly
	private static final Pattern[] patchPatterns = new Pattern[] {Pattern.compile("vulnerability|Vulnerability|vuln|Vuln|VULN[ #]*([0-9]+)")};
	private static final Logger logger = LogManager.getLogger(PatchFinder.class.getName());

	/**
	 * Thread object used for multithreaded patch finding
	 *
	 * @param possiblePatchSources map of CVEs to possible patch sources
	 * @param clonePath path to clone repos to
	 * @param timeoutMilli milliseconds until timeout // TODO for what
	 */
	public PatchFinderThread(HashMap<String, ArrayList<String>> possiblePatchSources, String clonePath, long timeoutMilli) {
		this.cvePatchEntry = possiblePatchSources;
		this.clonePath = clonePath;
		this.timeoutMilli = timeoutMilli;
	}

	/**
	 * Used for cloning, crawling, and deleting product repos to find patch commits
	 */
	@Override
	public void run() {
		final long totalStart = System.currentTimeMillis();

		final ArrayList<PatchCommit> foundPatchCommits = new ArrayList<>();

		// Order sources by repo size ascending
		final HashMap<String, ArrayList<Integer>> sourceCountMap = new HashMap<>();
		cvePatchEntry.forEach((c, v) -> sourceCountMap.put(c, orderSources(cvePatchEntry.get(c))));

		// For each CVE, iterate through the list of possible patch sources and
		// Clone/Scrape the repo for patch commits (if any)
		for (String cve : cvePatchEntry.keySet()) {
			final ArrayList<Integer> counts = sourceCountMap.get(cve);
			int i = 0;
			for (String patchSource: cvePatchEntry.get(cve)) {
				findPatchCommits(foundPatchCommits, cve, patchSource, counts.get(i));
				i++;
			}
		}

		//TODO: Instead of collecting patch commits for a final insertion, change getPatchCommits
		// to addAndInsertPatchCommits, so they program is not dependant on run completion

		// Add found commits to total list after finished
		PatchFinder.getPatchCommits().addAll(foundPatchCommits); // TODO: This may be causing race conditions

		final long delta = (System.currentTimeMillis() - totalStart) / 1000;
		logger.info("Done scraping {} patch commits from CVE(s) {} in {} seconds", foundPatchCommits.size(), cvePatchEntry.keySet(), delta);
	}

	/**
	 * Sort sources by repo size to improve run performance
	 *
	 * @param sources sources to sort
	 * @return list of source counts (1:1 with sorted sources list)
	 */
	private ArrayList<Integer> orderSources(ArrayList<String> sources) {
		// Map commit counts to their respective sources
		final HashMap<String, Integer> sourceCounts = new HashMap<>(sources.size());
		sources.forEach(s -> sourceCounts.put(s, getCommitCount(s)));

		// Sort list based on collected counts
		sources.sort(Comparator.comparingInt(sourceCounts::get));

		// Return counts list
		final ArrayList<Integer> counts = new ArrayList<>(sourceCounts.values());
		Collections.sort(counts);
		return counts;
	}

	/**
	 * Gets the commit count from a given source page
	 *
	 * @param source page to scrape
	 * @return found commit count
	 */
	private int getCommitCount(String source) {
		try {
			final long connStart = System.nanoTime();

			// Build connection object and execute connection operation
			final Connection conn = Jsoup.connect(source).timeout((int) this.timeoutMilli);
			conn.execute();

			// Get response
			final Connection.Response response = conn.response();

			// Get response code
			final int responseCode = response.statusCode();

			// Disallow invalid responses
			if (responseCode < 200 || responseCode >= 300) {
				throw new IllegalArgumentException("Received invalid response code " + responseCode);
			}

			// Log connection stats
			logger.info("Connection to URL '{}' successful. Done in {} ms",
					source,
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
				throw new IOException("Failed to extract commit count");
			}
			logger.info("Found {} commits on the master branch @ URL '{}'", commitCount, source);
			return commitCount;
		} catch (Exception e) {
			logger.error("Failed to parse commit count from URL '{}': {}", source, e.toString());
			return 0;
		}
	}

	/**
	 * Finds patch commits from a given patch source via either cloning or web scraping, based on repo size
	 *
	 * @param foundPatchCommits output list of found patch commits
	 * @param cve cve being analyzed
	 * @param patchSource patch source being scraped
	 * @param commitCount number of commits in the patch source
	 */
	private synchronized void findPatchCommits(ArrayList<PatchCommit> foundPatchCommits, String cve, String patchSource, int commitCount) {
		try {
			// Process found repository based on size (commit count on master branch)

			// If commit count is under threshold, scrape commits from url
			if(commitCount <= PatchFinderEnvVars.getCloneCommitThreshold())
				findPatchCommitsFromUrl(foundPatchCommits, cve, patchSource, commitCount);
			// If not over limit, clone repo to parse commits
			else if(commitCount <= PatchFinderEnvVars.getCloneCommitLimit())
				findPatchCommitsFromRepo(foundPatchCommits, cve, patchSource);
			// Otherwise, handle extra large repo
			else
				throw new IllegalArgumentException(
						"REPO SIZE OVER COMMIT_LIMIT, IT WILL NOT BE SCRAPED OR CLONED (" +
						commitCount +
						" > " +
						PatchFinderEnvVars.getCloneCommitLimit() + ")"
				);

		} catch (Exception e) {
			logger.error("Failed to find patch from source {} for CVE {}: {}", patchSource, cve, e.toString());
		}
	}

	/**
	 * Scrapes patch commits from a given url via pagination
	 *
	 * @param foundPatchCommits output list of found patch commits
	 * @param cve cve being analyzed
	 * @param patchSource patch source being scraped
	 * @param commitCount number of commits in the patch source
	 */
	private void findPatchCommitsFromUrl(ArrayList<PatchCommit> foundPatchCommits, String cve, String patchSource, int commitCount) {
		// Define page range
		final int numPages = (int) Math.ceil((double) commitCount / 35);
		final String baseCommitsUrl = patchSource + "/commits";

		// Query first page and get HEAD commit
		try {
			final Elements firstPageCommitObjects = getCommitObjects(baseCommitsUrl);

			// Ensure at least one commit was found
			if (firstPageCommitObjects.size() == 0) {
				throw new IOException("Failed to extract commits from page data");
			}

			// Extract the head commit SHA for pagination
			final String[] headCommitParts = firstPageCommitObjects.first().attr("href").split("/");
			final String headCommitEndpoint = headCommitParts[headCommitParts.length - 1];

			// Parse first page objects
			parseCommitObjects(foundPatchCommits, cve, firstPageCommitObjects);

			// Generate list of page URLs to query with head commit SHA
			final List<String> pageUrls = new ArrayList<>();
			for (int i = 34; i < (numPages * 35) - 35; i += 35) {
				pageUrls.add(baseCommitsUrl + "&after=" + headCommitEndpoint + "+" + i);
			}

			for (String url : pageUrls) {
				// Extract commit objects from URL
				final Elements commitObjects = getCommitObjects(url);

				// Ensure at least one object was found
				if (commitObjects.size() == 0) {
					logger.warn("Failed to find commit objects from URL '{}'", url);
					continue;
				}

				// Iterate over found commit objects, then build and store PatchCommit objects
				parseCommitObjects(foundPatchCommits, cve, commitObjects);
			}

		} catch (IOException e) {
			logger.error("Failed to find patch commits from URL '{}': {}", patchSource, e);
		}
	}

	/**
	 * Clones and finds patch commits from a given patch source
	 *
	 * @param foundPatchCommits output list of found patch commits
	 * @param cve cve being analyzed
	 * @param patchSource patch source being cloned
	 */
	private void findPatchCommitsFromRepo(ArrayList<PatchCommit> foundPatchCommits, String cve, String patchSource) {
		try {
			// Split source URI into parts to build local download path string
			final String[] sourceParts = patchSource.split("/");
			final int len = sourceParts.length;

			// Add vendor and product name from URI
			String localDownloadLoc = clonePath + "/" + cve + "-" + sourceParts[len - 2] + "-" + sourceParts[len - 1];

			// Clone git repo
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

			// TODO: Fix, as we need to prevent accumulation of repos if possible
			// Delete repo when done
//			gitController.deleteRepo();
		} catch (Exception e) {
			logger.error("ERROR: Failed to find patch from source {} for CVE {}\n{}", patchSource, cve, e.toString());
			e.printStackTrace();
		}
	}

	/**
	 * Parses commit objects from the given commit elements into output list
	 *
	 * @param foundPatchCommits output list of found patch commits
	 * @param cve cve being analyzed
	 * @param commitElements collection of commit elements
	 */
	private void parseCommitObjects(List<PatchCommit> foundPatchCommits, String cve, Elements commitElements) {
		// Check if the commit message matches any of the regex provided
		for (Pattern pattern : patchPatterns) {
			for (Element object : commitElements) {
				Matcher matcher = pattern.matcher(object.text());
				// If found the CVE ID is found, add the patch commit to the returned list
				if (matcher.find() || object.text().contains(cve)) {
					String commitUrl = object.attr("href");
					logger.info("Found patch commit @ URL '{}'", commitUrl);

					try {
						// Connect to the commit URL and retrieve the unified diff
						Document commitPage = Jsoup.connect(commitUrl).get();
						Elements diffElements = commitPage.select("div.file-actions");
						String unifiedDiffString = diffElements.text();

						// Extract the commit timeline, time to patch, and lines changed from the commit page
						Elements timelineElements = commitPage.select("div.timeline-item");
						List<String> timelineString = parseTimeline(timelineElements);
						String timeToPatch = extractTimeToPatch(commitPage);
						int linesChanged = extractLinesChanged(commitPage);
						List<String> commitTimeline = new ArrayList<>(); // Create a new commit timeline list
						String commitHash = matcher.group(1);

						commitTimeline.add(commitHash); // Add the current commit hash to the commit timeline

						PatchCommit patchCommit = new PatchCommit(
								commitUrl,
								cve,
								object.text(),
								new Date(object.attr("commitTime")),
								object.text(),
								unifiedDiffString, // unifiedDiff
								commitTimeline, // timeline
								timeToPatch, // timeToPatch
								linesChanged // linesChanged
						);

						foundPatchCommits.add(patchCommit);
					} catch (IOException e) {
						logger.error("Failed to scrape unified diff from commit URL '{}': {}", commitUrl, e);
					}
				}
			}
		}
	}

	/**
	 * Parses a "timeline" list of commits from the given timeline elements
	 * @param timelineElements collection of timeline elements
	 * @return parsed timeline elements
	 */
	private List<String> parseTimeline(Elements timelineElements) {
		List<String> timeline = new ArrayList<>();

		for (Element timelineElement : timelineElements) {
			String commitHash = timelineElement.text();
			timeline.add(commitHash);
		}

		return timeline;
	}

	/** // TODO: Is this accurate?
	 * Extracts the date of the patch commit
	 * @param commitPage DOM to extract from
	 * @return extracted time to patch
	 */
	private String extractTimeToPatch(Document commitPage) {
		Element timeToPatchElement = commitPage.selectFirst("relative-time[datetime]:not(.commit-author-date)");
		if (timeToPatchElement != null) {
			return timeToPatchElement.attr("datetime");
		}
		return null;
	}

	/**
	 * Extracts the number of lines changed from the given document object model
	 * @param commitPage DOM to extract from
	 * @return extracted lines changed count
	 */
	private int extractLinesChanged(Document commitPage) {
		Element linesChangedElement = commitPage.selectFirst("span.text-mono");
		if (linesChangedElement != null) {
			String linesChangedText = linesChangedElement.text();
			// Extract the integer value from the text
			try {
				return Integer.parseInt(linesChangedText.replaceAll("[^0-9]", ""));
			} catch (NumberFormatException e) {
				logger.error("Failed to extract lines changed from commit page: {}", e.getMessage());
			}
		}
		return 0;
	}

	/**
	 * Scrapes and returns commit elements from a given Github url
	 * @param url url to scrape
	 * @return found commit elements
	 */
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

					// Store commit description separately
					final String description = container.select("pre").text();
					messageElement.attr("commitDescription", description);
				} else {
					// Store commit description as the commit message if there is no separate description
					final String description = container.select("pre").text();
					messageElement.html(description);
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
