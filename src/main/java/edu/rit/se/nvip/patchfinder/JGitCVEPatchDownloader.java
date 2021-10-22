package edu.rit.se.nvip.patchfinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.util.FileUtils;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.patchfinder.commits.JGitParser;

public final class JGitCVEPatchDownloader {

	private static final Logger logger = LogManager.getLogger(JGitCVEPatchDownloader.class.getName());
	private static JGitParser previousRepo = null;
	private static final DatabaseHelper db = DatabaseHelper.getInstance();

	/**
	 * TODO: Update this so that it can pull CVE IDs from vulnerability table for
	 * the 3rd parameter Parses out patch data from a preset list of repos within a
	 * csv file
	 * 
	 * @param repoFile
	 * @param clonePath
	 * @throws IOException
	 */
	public static void parse(File repoFile, String clonePath) throws IOException {
		List<String> repos = processInputFile(repoFile);
		repos = new ArrayList<>(new HashSet<>(repos));
		for (int i = 0; i < repos.size(); i++) {
			pullCommitData(repos.get(i), clonePath, "");
		}
	}

	/**
	 * Extract Method called multiple times for parsing an individual URL
	 * 
	 * @param clonePath
	 * @throws SQLException
	 * @throws IOException
	 * @throws GitAPIException
	 */
	public static void parse(String clonePath, int limit) throws IOException {

		File dir = new File(clonePath);
		FileUtils.delete(dir, 1);

		try {

			for (Entry<Integer, String> source : db.getVulnIdPatchSource(limit).entrySet()) {
				pullCommitData(source.getValue(), clonePath, db.getCveId(source.getKey() + ""));
			}

		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}

	/**
	 * Extract Method used for pulling commit data from a repo vi a source link and
	 * parsing commits for any commits related to CVEs
	 * 
	 * @param sourceURL
	 * @param clonePath
	 * @throws IOException
	 * @throws GitAPIException
	 */
	private static void pullCommitData(String sourceURL, String clonePath, String cveId) {

		JGitParser parser = new JGitParser(sourceURL + ".git", clonePath);

		parser.cloneRepository();

		Map<java.util.Date, ArrayList<String>> commits = parser.parseCommits(cveId);

		if (commits.isEmpty()) {
			deletePatchSource(sourceURL);
		} else {
			for (java.util.Date commit : commits.keySet()) {
				insertPatchCommitData(sourceURL, commits.get(commit).get(0), commit, commits.get(commit).get(1));
			}
		}

		// Delete previously cloned local repo after storing
		// patch/commit data (to ensure the .pack file is closed in the .git directory)
		if (previousRepo != null) {
			previousRepo.deleteRepository();
		}
		previousRepo = parser;

	}

	/**
	 * Updates patch field by adding provided commit message and date that was
	 * pulled when parsing commits
	 * 
	 * @param commitDate
	 * @param commitMessage
	 */
	private static void insertPatchCommitData(String sourceURL, String commitId, java.util.Date commitDate,
			String commitMessage) {

		logger.info("Inserting commit data to patchcommit table...");
		if (commitMessage.length() > 300) {
			commitMessage = commitMessage.substring(0, 299);
		}

		commitId = commitId.split(" ")[1];

		try {
			int id = db.getPatchSourceId(sourceURL);
			db.insertPatchCommit(id, sourceURL, commitId, commitDate, commitMessage);
			logger.info("Inserted commit from source ID: " + id);

		} catch (Exception e) {
			logger.error((e.getMessage()));
		}
	}

	/**
	 * Method used to delete Patch entries that lead to no commit data related to
	 * CVEs or patches
	 * 
	 * @param sourceURL
	 */
	private static void deletePatchSource(String sourceURL) {
		logger.info("Deleting patch from database...");

		try {

			int id = db.getPatchSourceId(sourceURL);

			if (id != -1) {
				// Delete Patch Entry
				db.deleteCommits(id);

				// Delete Patch URL Entry
				db.deletePatchURL(id);
			}

		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}


	/**
	 *
	 * @param file
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private static List<String> processInputFile(File file) throws FileNotFoundException, IOException {
		ArrayList<String> repos = new ArrayList<String>();

		BufferedReader br = new BufferedReader(new FileReader(file));
		String line;
		br.readLine(); // ignoring id in csv
		while ((line = br.readLine()) != null) {
			String[] entries = line.split(",");

			String repo = entries[0].trim();
			repos.add(repo.replace("https://api.", "https://").replace(".com/repos/", ".com/"));
		}
		return repos;
	}
}
