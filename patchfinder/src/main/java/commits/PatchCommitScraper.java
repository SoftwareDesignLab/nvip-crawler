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
import org.eclipse.jgit.diff.Edit;
import org.eclipse.jgit.lib.*;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.treewalk.CanonicalTreeParser;
import org.eclipse.jgit.util.io.DisabledOutputStream;

/**
 *	For Scraping repo commits for possible patch commits
 */
public class PatchCommitScraper {

	private static final Logger logger = LogManager.getLogger(PatchCommitScraper.class.getName());
	private final String localDownloadLoc;
	private final String repoSource;
	private RevCommit vulnerableCommit; // Added

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
	public List<PatchCommit> parseCommits(String cveId, Pattern[] patchPatterns) {
		List<PatchCommit> patchCommits = new ArrayList<>();

		logger.info("Grabbing Commits List for repo @ {}...", localDownloadLoc);

		// Initialize commit list form the repo's .git folder
		try (final Repository repository = new FileRepositoryBuilder().setGitDir(new File(localDownloadLoc+"/.git")).build()){
			try(final Git git = new Git(repository)) {
				// Iterate through each commit and check if there's a commit message that contains a CVE ID
				// or the 'vulnerability' keyword
				// TODO: Test now that localDownloadLoc is fixed
				final ObjectId startingRevision = repository.resolve("refs/heads/master");
				if(startingRevision != null || true) {
					// TODO: Catch NoHeadException, possibly due to empty repos, investigate further
					final Iterable<RevCommit> commits = git.log()/*.add(startingRevision)*/.call();

					int ignoredCounter = 0;

					for (RevCommit commit : commits) {
						// Check if the commit message matches any of the regex provided
						for (Pattern pattern : patchPatterns) {
							Matcher matcher = pattern.matcher(commit.getFullMessage());
							// If found the CVE ID is found, add the patch commit to the returned list
							if (matcher.find() || commit.getFullMessage().contains(cveId)) {
								String commitUrl = repository.getConfig().getString("remote", "origin", "url");
								logger.info("Found patch commit @ {} in repo {}", commitUrl, localDownloadLoc);
								String unifiedDiff = generateUnifiedDiff(git, commit);
//								List<String> commitTimeLine = calculateCommitTimeline(repository, startingRevision, commit);
//								logger.info("Commit timeline: {}", commitTimeLine);
								int linesChanged = getLinesChanged(repository, commit);
								logger.info("Lines changed: {}", linesChanged);
								PatchCommit patchCommit = new PatchCommit(commitUrl, cveId, commit.getName(), new Date(commit.getCommitTime() * 1000L), commit.getFullMessage(), unifiedDiff);
								patchCommits.add(patchCommit);
							} else ignoredCounter++;
						}
					}

//					logger.info("Ignored {} non-patch commits", ignoredCounter);

					if (patchCommits.isEmpty()) {
						logger.info("No patches for CVE '{}' found in repo '{}' ", cveId, localDownloadLoc.split("/")[4]);
					}
				} else logger.warn("Could not get starting revision from repo '{}'", localDownloadLoc.split("/")[4]);
			}
		} catch (IOException | GitAPIException e) {
			logger.error("ERROR: Failed to scrape repo @ {} for patch commits for CVE {}\n{}", repoSource, cveId, e);
		}

		return patchCommits;
	}

	/**
	 * Generate the unified diff for a specific commit.
	 *
	 * @param git    the Git object
	 * @param commit the commit for which to generate the unified diff
	 * @return the unified diff as a string
	 */
	private String generateUnifiedDiff(Git git, RevCommit commit) {
		try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			 DiffFormatter formatter = new DiffFormatter(outputStream)) {
			formatter.setRepository(git.getRepository());
			formatter.setContext(0); // Set context lines to 0 to exclude unchanged lines
			formatter.format(commit.getParent(0), commit);

			String unifiedDiff = outputStream.toString();

			// Find the start of the patch section
			int patchStartIndex = unifiedDiff.indexOf("@@");

			if (patchStartIndex >= 0) {
				// Extract the patch section
				unifiedDiff = unifiedDiff.substring(patchStartIndex);
			} else {
				logger.warn("Failed to find patch section in the unified diff for commit {}", commit.getName());
				unifiedDiff = ""; // Return empty string if patch section is not found
			}

			return unifiedDiff;
		} catch (IOException e) {
			logger.error("Failed to generate unified diff for commit {}", commit.getName());
			return "";
		}
	}
	/**
	 * Get the CanonicalTreeParser for a given repository and object ID.
	 *
	 * @param repository the Git repository
	 * @param objectId   the object ID
	 * @return the CanonicalTreeParser
	 * @throws IOException if an error occurs while accessing the repository
	 */
	private CanonicalTreeParser getCanonicalTreeParser(Repository repository, ObjectId objectId) throws IOException {
		try (RevWalk revWalk = new RevWalk(repository)) {
			RevCommit commit = revWalk.parseCommit(objectId);
			ObjectId treeId = commit.getTree().getId();
			try (ObjectReader objectReader = repository.newObjectReader()) {
				CanonicalTreeParser treeParser = new CanonicalTreeParser();
				treeParser.reset(objectReader, treeId);
				return treeParser;
			}
		}
	}

	/**
	 * prepare a timeline of commits between the vulnerable commit, and the patch commit. Keep track of timeline, estimate how long it took to patch, how many lines needed to be change.
	 * @param repository
	 * @param startingRevision
	 * @param patchCommit
	 * @return
	 * @throws IOException
	 * @throws GitAPIException
	 */
	private List<String> calculateCommitTimeline(Repository repository, ObjectId startingRevision, RevCommit patchCommit) throws IOException, GitAPIException {
		List<String> commitTimeline = new ArrayList<>();

		// Get the canonical tree parser for the starting revision
		CanonicalTreeParser startingTreeParser = getCanonicalTreeParser(repository, startingRevision);

		// Get the canonical tree parser for the patch commit
		CanonicalTreeParser patchTreeParser = getCanonicalTreeParser(repository, patchCommit);

		// Get the list of diffs between the starting revision and the patch commit
		try (Git git = new Git(repository)) {
			List<DiffEntry> diffs = git.diff().setNewTree(patchTreeParser).setOldTree(startingTreeParser).call();

			// Iterate through the diffs and add the commit messages to the timeline
			for (DiffEntry diff : diffs) {
				commitTimeline.add(diff.getChangeType().toString() + " " + diff.getNewPath());
			}
		}

		return commitTimeline;
	}

	/**
	 * Get the lines of code changed in a commit.
	 * @param repository the Git repository
	 * @param commit the commit
	 *
	 * @return the number of lines changed
	 */
	private int getLinesChanged(Repository repository, RevCommit commit) {
		try (Git git = new Git(repository)) {
			CanonicalTreeParser treeParser = getCanonicalTreeParser(repository, commit);
			if (treeParser != null) {
				RevCommit parentCommit = commit.getParents()[0];
				CanonicalTreeParser parentTreeParser = getCanonicalTreeParser(repository, parentCommit);

				List<DiffEntry> diffs = git.diff()
						.setNewTree(treeParser)
						.setOldTree(parentTreeParser)
						.call();

				int linesChanged = 0;
				for (DiffEntry diff : diffs) {
					linesChanged += countLinesChanged(diff, repository);
				}

				return linesChanged;
			}
		} catch (IOException | GitAPIException e) {
			logger.error("Failed to get lines changed for commit {}", commit.getName(), e);
		}

		return 0;
	}

	private int countLinesChanged(DiffEntry diffEntry, Repository repository) throws IOException {
		int linesChanged = 0;
		try (DiffFormatter diffFormatter = new DiffFormatter(DisabledOutputStream.INSTANCE)) {
			diffFormatter.setRepository(repository);
			List<Edit> edits = diffFormatter.toFileHeader(diffEntry).toEditList();
			for (Edit edit : edits) {
				linesChanged += edit.getEndB() - edit.getBeginB();
			}
		}
		return linesChanged;
	}
}
