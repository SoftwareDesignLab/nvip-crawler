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
package edu.rit.se.nvip.patchfinder.commits;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.internal.storage.file.FileRepository;
import org.eclipse.jgit.internal.storage.file.WindowCache;
import org.eclipse.jgit.lib.ProgressMonitor;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.storage.file.WindowCacheConfig;
import org.eclipse.jgit.util.FileUtils;

/**
 *	For Scraping repo commits for possible patch commits
 */
public class PatchCommitScraper {

	private static final Logger logger = LogManager.getLogger(PatchCommitScraper.class.getName());

	private static final String REGEX_VULN = "vulnerability|Vulnerability|vuln|Vuln|VULN[ #]*([0-9]+)";
	private static final String REGEX_CVE = "(CVE[-]*[0-9]*[-]*[0-9]*)";
	private static final Pattern PATTERN_VULN = Pattern.compile(REGEX_VULN);
	private static final Pattern PATTERN_CVES = Pattern.compile(REGEX_CVE);
	private Git git;
	private final List<PatchCommit> fixCommits;

	private final String localDownloadLoc;

	public PatchCommitScraper(String localDownloadLoc) {
		this.localDownloadLoc = localDownloadLoc;
	}

	/**
	 * Deletes repository from storage (used after patch data is pulled)
	 */
	public void deleteRepository() {
		logger.info("Deleting Repo...");
		try {
			WindowCacheConfig config = new WindowCacheConfig();
			config.setPackedGitMMAP(true);
			WindowCache.reconfigure(config);

			File dir = new File(localDownloadLoc + File.separator + projectName);
			this.git.close();

			FileUtils.delete(dir, 1);

			logger.info("Repo " + projectName + " deleted successfully!");
		} catch (IOException e) {
			logger.info(e.getMessage());
		}
	}

	/**
	 * Collects all commits from a repo and returns them in a list
	 * 
	 * @return
	 */
	private List<RevCommit> getAllCommitList() {
		List<RevCommit> revCommits = new ArrayList<>();
		try {
			for (RevCommit rev : git.log().call()) {
				revCommits.add(rev);
			}
		} catch (GitAPIException e) {
			e.getMessage();
			logger.error("ERRRO: Failed to get list of commits for repo @ {}\n{}", this.localDownloadLoc,
					e.toString());
		}
		return revCommits;
	}

	/**
	 * Parse commits to prepare for extraction of patches for a repo. Uses preset
	 * Regex to find commits related to CVEs or bugs for patches
	 * 
	 * @throws IOException
	 * @throws GitAPIException
	 * @return
	 */
	public Map<Date, ArrayList<String>> parseCommits(String cveId) {
		logger.info("Grabbing Commits List for repo @ {}...", this.localDownloadLoc);
		List<RevCommit> allCommits = this.getAllCommitList();

		for (RevCommit repoCommit : allCommits) {
			String message = repoCommit.getFullMessage();
			Matcher matcherCve = PATTERN_CVES.matcher(message);
			List<String> foundCves = new ArrayList<>();

			List<String> foundVulns = new ArrayList<>();
			Matcher matcherVuln = PATTERN_VULN.matcher(message);

			// Search for 'CVE' commits
			if (matcherCve.find()) {

				boolean cveCheck = true;

				if (matcherCve.group(0).contains("CVE-")) {
					if (matcherCve.group(0).contains(cveId)) {
						logger.info("Found CVE Commit " + matcherCve.group(0));
						foundCves.add(matcherCve.group(0));
					} else {
						cveCheck = false;
					}
				}

				if (cveCheck) {
					logger.info("Found CVE Commit " + matcherCve.group(0));
					foundCves.add(matcherCve.group(0));
				}
			}

			// Search for 'Vulnerability' commits
			else if (matcherVuln.find()) {
				logger.info("Found Vuln Commit " + matcherVuln.group(0));
				foundVulns.add(matcherVuln.group(0));
			}

			if (!foundCves.isEmpty() || !foundVulns.isEmpty()) {
				PatchCommit githubCommit = new PatchCommit(repoCommit.getName(), repoCommit);
				this.fixCommits.add(githubCommit);
			}
		}

		return extractJGithubComits(fixCommits);

	}

	private Git getGit() {
		return git;
	}

	/**
	 * Generate a TreeParser from a Tree that's obtained from a given commit to
	 * allow for no inspection duplicates
	 *
	 * @return
	 * @return
	 * @param fixCommits
	 */
	private Map<Date, ArrayList<String>> extractJGithubComits(List<PatchCommit> fixCommits) {

		Map<Date, ArrayList<String>> commits = new HashMap<>();

		for (PatchCommit fixCommit : fixCommits) {

			ArrayList<String> commitData = new ArrayList<>();

			commitData.add(fixCommit.getCommit().getId().toString());
			commitData.add(fixCommit.getCommit().getFullMessage());

			commits.put(fixCommit.getCommit().getAuthorIdent().getWhen(), commitData);
		}

		logger.info("Commits from repo " + projectName + " parsed successfully!");
		return commits;

	}
}
