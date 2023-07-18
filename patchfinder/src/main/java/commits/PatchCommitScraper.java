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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
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
 *
 * @author Dylan Mulligan
 */
public class PatchCommitScraper {

	private static final Logger logger = LogManager.getLogger(PatchCommitScraper.class.getName());
	private final String localDownloadLoc;
	private final String repoSource;
	private static final int UNI_DIFF_LIMIT = 500;

	private static final int COM_MESSAGE_LIMIT = 1000;

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

		final String[] localDownloadParts = localDownloadLoc.split("/");
		final String localName = localDownloadParts[localDownloadParts.length - 1];

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
								// Truncate unidiff to char limit
								if(unifiedDiff.length() > UNI_DIFF_LIMIT) {
									logger.warn("Unified diff was longer than UNI_DIFF_LIMIT ({}), and was truncated", UNI_DIFF_LIMIT);
									unifiedDiff = unifiedDiff.substring(0, UNI_DIFF_LIMIT);
								}
								List<String> commitTimeline = calculateCommitTimeline(repository, startingRevision, commit);
								int linesChanged = getLinesChanged(repository, commit);
								List<RevCommit> commitList = calculateCommitTimelineElapsed(repository, startingRevision, commit);
								Long timeToPatch = calculateTimeToPatch(commitList);
								String formattedTimeToPatch = formatTimeToPatch(timeToPatch);
								String commitMessage = commit.getFullMessage();
								if(commitMessage.length() > COM_MESSAGE_LIMIT) {
									logger.warn("Commit message was longer than COM_MESSAGE_LIMIT ({}), and was truncated", COM_MESSAGE_LIMIT);
									commitMessage = commitMessage.substring(0, COM_MESSAGE_LIMIT-3) + "...";
								}
								PatchCommit patchCommit = new PatchCommit(commitUrl, cveId, commit.getName(), new Date(commit.getCommitTime() * 1000L), commitMessage, unifiedDiff, commitTimeline, formattedTimeToPatch, linesChanged);
								patchCommits.add(patchCommit);
							} else ignoredCounter++;
						}
					}

//					logger.info("Ignored {} non-patch commits", ignoredCounter);

					if (patchCommits.isEmpty()) {
						logger.info("No patches for CVE '{}' found in repo '{}' ", cveId, localName);
					}
				} else logger.warn("Could not get starting revision from repo '{}'", localName);
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
	 * @param commit
	 * @return
	 * @throws IOException
	 * @throws GitAPIException
	 */
	private List<String> calculateCommitTimeline(Repository repository, ObjectId startingRevision, RevCommit commit) throws IOException {
		List<String> commitTimeline = new ArrayList<>();

		try (RevWalk walk = new RevWalk(repository)) {
			RevCommit currentCommit = commit;
			while (currentCommit != null && !currentCommit.getId().equals(startingRevision)) {
				commitTimeline.add(0, currentCommit.getId().abbreviate(7).name()); // Prepend commit hash
				if (currentCommit.getParentCount() > 0) {
					currentCommit = walk.parseCommit(currentCommit.getParent(0).getId());
				} else {
					break;
				}
			}
		}

		int commitCount = commitTimeline.size();
		if (commitCount > 2) {
			int displayedCommits = Math.min(commitCount, 11); // Maximum number of displayed commits (including first and last)
			List<String> displayedTimeline = new ArrayList<>();

			// Add first commit
			displayedTimeline.add(commitTimeline.get(0));

			// Add 9 commits in between (if available)
			int inBetweenCommits = displayedCommits - 2;
			for (int i = 1; i <= inBetweenCommits; i++) {
				displayedTimeline.add(commitTimeline.get(i));
			}

			// Add last commit
			displayedTimeline.add(commitTimeline.get(commitCount - 1));

			return displayedTimeline;
		}

		return commitTimeline;
	}


	private List<RevCommit> calculateCommitTimelineElapsed(Repository repository, ObjectId startingRevision, RevCommit commit) throws IOException {
		List<RevCommit> commitTimeline = new ArrayList<>();
		try (RevWalk walk = new RevWalk(repository)) {
			RevCommit currentCommit = commit;
			while (currentCommit != null && !currentCommit.getId().equals(startingRevision)) {
				commitTimeline.add(currentCommit);
				if (currentCommit.getParentCount() > 0) {
					currentCommit = walk.parseCommit(currentCommit.getParent(0).getId());
				} else {
					break;
				}
			}
		}

		int commitCount = commitTimeline.size();
		if (commitCount > 2) {
			int inBetweenCommits = commitCount - 2; // Number of commits in between first and last
			int maxDisplayedCommits = 8; // Maximum number of displayed commits (including first and last)
			int displayedCommits = Math.min(maxDisplayedCommits, inBetweenCommits + 2);
			int inBetweenLimit = displayedCommits - 2; // Limit of commits in between
			List<RevCommit> displayedTimeline = new ArrayList<>();
			displayedTimeline.add(commitTimeline.get(0)); // First commit
			displayedTimeline.addAll(commitTimeline.subList(1, 1 + inBetweenLimit)); // Commits in between
			displayedTimeline.add(commitTimeline.get(commitCount - 1)); // Last commit
			return displayedTimeline;
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

	private long calculateTimeToPatch(List<RevCommit> commitTimeline) {
		if (commitTimeline.size() <= 1) {
			// If there are no or only one commit in the timeline, return 0 indicating no patch time
			return 0;
		}

		// Calculate the time difference between the initial commit and the patch commit in milliseconds
		RevCommit initialCommit = commitTimeline.get(0);
		RevCommit patchCommit = commitTimeline.get(commitTimeline.size() - 1);
		long initialCommitTime = initialCommit.getCommitTime() * 1000L;
		long patchCommitTime = patchCommit.getCommitTime() * 1000L;
		long elapsedMillis = patchCommitTime - initialCommitTime;

		// Convert milliseconds to days and ensure it's a positive value
		return Math.abs(elapsedMillis / (1000 * 60 * 60 * 24));
	}

	private String formatTimeToPatch(long elapsedHours) {
		long days = elapsedHours / 24;
		long hours = elapsedHours % 24;

		StringBuilder formattedTime = new StringBuilder();

		if (days > 0) {
			formattedTime.append(days).append(" days ");
		}
		if (hours > 0) {
			formattedTime.append(hours).append(" hours");
		}

		return formattedTime.toString().trim();
	}
}
