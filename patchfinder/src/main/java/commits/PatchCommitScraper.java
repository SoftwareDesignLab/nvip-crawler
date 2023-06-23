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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.time.*;
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
import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.lib.*;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.treewalk.CanonicalTreeParser;

/**
 *	For Scraping repo commits for possible patch commits
 */
public class PatchCommitScraper {

	private static final Logger logger = LogManager.getLogger(PatchCommitScraper.class.getName());
	private static final Pattern[] patchRegex = new Pattern[]{Pattern.compile("vulnerability|Vulnerability|vuln|Vuln|VULN[ #]*([0-9]+)")};
	private final String localDownloadLoc;
	private final String repoSource;
	private RevCommit vulnerableCommit; // Added

	public PatchCommitScraper(String localDownloadLoc, String repoSource) {
		this.localDownloadLoc = localDownloadLoc;
		this.repoSource = repoSource;
	}

	public List<PatchCommit> parseCommits(String cveId) {
		List<PatchCommit> patchCommits = new ArrayList<>();

		logger.info("Grabbing Commits List for repo @ {}...", localDownloadLoc);

		try (final Repository repository = new FileRepositoryBuilder().setGitDir(new File(localDownloadLoc + "/.git")).build()) {
			try (final Git git = new Git(repository)) {
				final ObjectId startingRevision = repository.resolve("refs/heads/master");
				if (startingRevision != null || true) {
					final Iterable<RevCommit> commits = git.log().call();

					int ignoredCounter = 0;

					for (RevCommit commit : commits) {
						for (Pattern pattern : patchRegex) {
							Matcher matcher = pattern.matcher(commit.getFullMessage());
							if (matcher.find() || commit.getFullMessage().contains(cveId)) {
								String commitUrl = repository.getConfig().getString("remote", "origin", "url");
								logger.info("Found patch commit @ {} in repo {}", commitUrl, localDownloadLoc);
								String unifiedDiff = generateUnifiedDiff(git, commit);

								if (vulnerableCommit != null) { // Added
									long timeToPatch = calculateTimeToPatch(vulnerableCommit, commit); // Added
									int linesChanged = countLinesChanged(unifiedDiff); // Added

									PatchCommit patchCommit = new PatchCommit(commitUrl, cveId, commit.getName(),
											new Date(commit.getCommitTime() * 1000L), commit.getFullMessage(), unifiedDiff);
									patchCommit.setTimeToPatch(timeToPatch);
									patchCommit.setLinesChanged(linesChanged);

									patchCommits.add(patchCommit);
								}
							} else ignoredCounter++;
						}
					}

					if (patchCommits.isEmpty()) {
						logger.info("No patches for CVE '{}' found in repo '{}'", cveId, localDownloadLoc.split("/")[4]);
					}
				} else logger.warn("Could not get starting revision from repo '{}'", localDownloadLoc.split("/")[4]);
			}
		} catch (IOException | GitAPIException e) {
			logger.error("ERROR: Failed to scrape repo @ {} for patch commits for CVE {}\n{}", repoSource, cveId, e);
		}

		return patchCommits;
	}

	private String generateUnifiedDiff(Git git, RevCommit commit) {
		try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			 DiffFormatter formatter = new DiffFormatter(outputStream)) {
			formatter.setRepository(git.getRepository());
			formatter.setContext(0);
			formatter.format(commit.getParent(0), commit);

			String unifiedDiff = outputStream.toString();

			int patchStartIndex = unifiedDiff.indexOf("@@");

			if (patchStartIndex >= 0) {
				unifiedDiff = unifiedDiff.substring(patchStartIndex);
			} else {
				logger.warn("Failed to find patch section in the unified diff for commit {}", commit.getName());
				unifiedDiff = "";
			}

			return unifiedDiff;
		} catch (IOException e) {
			logger.error("Failed to generate unified diff for commit {}", commit.getName());
			return "";
		}
	}

	private long calculateTimeToPatch(RevCommit vulnerableCommit, RevCommit patchCommit) {
		return patchCommit.getCommitTime() - vulnerableCommit.getCommitTime();
	}

	private int countLinesChanged(String unifiedDiff) {
		int linesChanged = 0;

		for (String line : unifiedDiff.split("\n")) {
			if (line.startsWith("+") || line.startsWith("-")) {
				linesChanged++;
			}
		}

		return linesChanged;
	}
}