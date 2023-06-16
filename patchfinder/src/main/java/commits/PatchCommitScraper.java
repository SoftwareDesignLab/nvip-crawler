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
package commits;

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
import org.eclipse.jgit.lib.*;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;

/**
 *	For Scraping repo commits for possible patch commits
 */
public class PatchCommitScraper {

	private static final Logger logger = LogManager.getLogger(PatchCommitScraper.class.getName());
	private static final Pattern[] patchRegex = new Pattern[] {Pattern.compile("vulnerability|Vulnerability|vuln|Vuln|VULN[ #]*([0-9]+)")};
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
		List<PatchCommit> patchCommits = new ArrayList<>();

		logger.info("Grabbing Commits List for repo @ {}...", localDownloadLoc);

		// Initialize commit list form the repo's .git folder
		try (final Repository repository = new FileRepositoryBuilder().setGitDir(new File(localDownloadLoc+"/.git")).build()){
			try(final Git git = new Git(repository)) {
				// Iterate through each commit and check if there's a commit message that contains a CVE ID
				// or the 'vulnerability' keyword
				final ObjectId startingRevision = repository.resolve("refs/heads/master");
				if(startingRevision != null) {
					final Iterable<RevCommit> commits = git.log().add(startingRevision).call();

					int ignoredCounter = 0;

					for (RevCommit commit : commits) {
						// Check if the commit message matches any of the regex provided
						for (Pattern pattern : patchRegex) {
							Matcher matcher = pattern.matcher(commit.getFullMessage());
							// If found the CVE ID is found, add the patch commit to the returned list
							if (matcher.find() || commit.getFullMessage().contains(cveId)) {
								String commitUrl = repository.getConfig().getString("remote", "origin", "url");
								LocalDateTime commitDateTime = LocalDateTime.ofInstant(
										Instant.ofEpochSecond(commit.getCommitTime()),
										ZoneId.systemDefault()
								);
								logger.info("Found patch commit @ {} in repo {}", commitUrl, localDownloadLoc);
								PatchCommit patchCommit = new PatchCommit(commitUrl, cveId, commit.getName(), commitDateTime, commit.getFullMessage());
								patchCommits.add(patchCommit);
							} else ignoredCounter++;
						}
					}

					logger.info("Ignored {} non-patch commits", ignoredCounter);

					if (patchCommits.isEmpty()) {
						logger.info("No patches for CVE {} found in repo {} ", cveId, localDownloadLoc);
					}
				} else logger.warn("Could not get starting revision from repo {}", localDownloadLoc);
			}
		} catch (IOException | GitAPIException e) {
			logger.error("ERROR: Failed to scrape repo @ {} for patch commits for CVE {}\n{}", repoSource, cveId, e);
		}

		return patchCommits;
	}

}
