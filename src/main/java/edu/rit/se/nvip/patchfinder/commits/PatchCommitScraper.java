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
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
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
import org.eclipse.jgit.patch.Patch;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.storage.file.WindowCacheConfig;
import org.eclipse.jgit.util.FileUtils;

/**
 *	For Scraping repo commits for possible patch commits
 */
public class PatchCommitScraper {

	private static final Logger logger = LogManager.getLogger(PatchCommitScraper.class.getName());
	private static final String[] patchRegex = new String[] {"vulnerability|Vulnerability|vuln|Vuln|VULN[ #]*([0-9]+)", "(CVE[-]*[0-9]*[-]*[0-9]*)"};
	private final String localDownloadLoc;
	private final String repoSource;

	public PatchCommitScraper(String localDownloadLoc, String repoSource) {
		this.localDownloadLoc = localDownloadLoc;
		this.repoSource = repoSource;
	}

	/**
	 * Parse commits to prepare for extraction of patches for a repo. Uses preset
	 * Regex to find commits related to CVEs or bugs for patches
	 *
	 * @throws IOException
	 * @throws GitAPIException
	 * @return
	 */
	public List<PatchCommit> parseCommits(String cveId) {
		String repoLocation = this.localDownloadLoc + File.separator + this.repoSource;
		List<PatchCommit> patchCommits = new ArrayList<>();

		logger.info("Grabbing Commits List for repo @ {}...", repoLocation);
		try {
			// Read configuration from environment variables
			// and scan up the file system tree
			FileRepositoryBuilder repositoryBuilder = new FileRepositoryBuilder();
			Repository repository = repositoryBuilder.setGitDir(new File(repoLocation))
					.readEnvironment()
					.findGitDir()
					.build();

			// Iterate through each commit and check if there's a commit message that contains a CVE ID
			// or the 'vulnerability' keyword
			try (Git git = new Git(repository)) {
				Iterable<RevCommit> commits = git.log().all().call();
				for (RevCommit commit : commits) {
					// Check if the commit message matches any of the regex provided
					for (String regex: patchRegex) {
						Pattern pattern = Pattern.compile(regex);
						Matcher matcher = pattern.matcher(commit.getFullMessage());
						// If found, add the patch commit to the returned list
						if (matcher.find()) {
							String commitUrl = repository.getConfig().getString("remote", "origin", "url");
							LocalDateTime commitDateTime = LocalDateTime.ofInstant(
									Instant.ofEpochSecond(commit.getCommitTime()),
									ZoneId.systemDefault()
							);
							logger.info("Found patch commit @ {} for CVE {}", commitUrl, cveId);
							PatchCommit patchCommit = new PatchCommit(commitUrl,  cveId, commit.getName(), commitDateTime, commit.getFullMessage());
							patchCommits.add(patchCommit);
						}
					}

				}
			}
		} catch (IOException | GitAPIException e) {
			logger.error("ERROR: Failed to scrape repo @ {} for patch commits for CVE {}\n{}", repoSource, cveId, e);
			e.printStackTrace();
		}

		return patchCommits;
	}

}
