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
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.diff.RawTextComparator;
import org.eclipse.jgit.lib.*;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.treewalk.CanonicalTreeParser;

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
	 * Retrieve the unified diff for a specific commit in the repository.
	 *
	 * @param repository The Git repository.
	 * @param commit The commit for which to retrieve the unified diff.
	 * @return The unified diff as a string.
	 * @throws IOException If an I/O error occurs.
	 */
	private String getCommitUnifiedDiff(Repository repository, RevCommit commit) throws IOException {
		try (DiffFormatter diffFormatter = new DiffFormatter(new ByteArrayOutputStream())) {
			diffFormatter.setRepository(repository);
			diffFormatter.setDiffComparator(RawTextComparator.DEFAULT);
			diffFormatter.setDetectRenames(true);


			CanonicalTreeParser oldTreeParser = new CanonicalTreeParser();
			oldTreeParser.reset(repository.newObjectReader(), commit.getParents()[0].getTree());
			CanonicalTreeParser newTreeParser = new CanonicalTreeParser();
			newTreeParser.reset(repository.newObjectReader(), commit.getTree());


			ByteArrayOutputStream diffOutputStream = new ByteArrayOutputStream();
			diffFormatter.format(oldTreeParser, newTreeParser);
			return diffOutputStream.toString();
		}
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


		try (final Repository repository = new FileRepositoryBuilder().setGitDir(new File(localDownloadLoc + "/.git")).build()) {
			try (final Git git = new Git(repository)) {
				final ObjectId startingRevision = repository.resolve("refs/heads/master");
				if (startingRevision != null) {
					final Iterable<RevCommit> commits = git.log().add(startingRevision).call();


					int ignoredCounter = 0;


					for (RevCommit commit : commits) {
						for (Pattern pattern : patchRegex) {
							Matcher matcher = pattern.matcher(commit.getFullMessage());
							if (matcher.find() || commit.getFullMessage().contains(cveId)) {
								String commitUrl = repository.getConfig().getString("remote", "origin", "url");
								logger.info("Found patch commit @ {} in repo {}", commitUrl, localDownloadLoc);


								// Retrieve the unified diff for the commit
								String unifiedDiff;
								try {
									unifiedDiff = getCommitUnifiedDiff(repository, commit);
								} catch (IOException e) {
									logger.error("Failed to retrieve unified diff for commit: {}", commit.getName());
									unifiedDiff = "";
								}


								PatchCommit patchCommit = new PatchCommit(commitUrl, cveId, commit.getName(), commit.getCommitTime(), commit.getFullMessage(), unifiedDiff);
								patchCommits.add(patchCommit);
							} else {
								ignoredCounter++;
							}
						}
					}


					logger.info("Ignored {} non-patch commits", ignoredCounter);


					if (patchCommits.isEmpty()) {
						logger.info("No patches for CVE {} found in repo {} ", cveId, localDownloadLoc);
					}
				} else {
					logger.warn("Could not get starting revision from repo {}", localDownloadLoc);
				}
			}
		} catch (IOException | GitAPIException e) {
			logger.error("ERROR: Failed to scrape repo @ {} for patch commits for CVE {}\n{}", repoSource, cveId, e);
		}


		return patchCommits;
	}


}
