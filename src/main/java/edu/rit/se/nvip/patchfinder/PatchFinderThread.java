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
package edu.rit.se.nvip.patchfinder;

import java.util.*;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.patchfinder.commits.PatchCommit;
import edu.rit.se.nvip.patchfinder.commits.PatchCommitScraper;
import edu.rit.se.nvip.utils.GitController;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Runnable thread class for multithreaded patch finder
 *
 * Used for finding patches from sources defined in a provided list
 */
public class PatchFinderThread implements Runnable {
	private final HashMap<String, ArrayList<String>> cvePatchEntry;
	private final String clonePath;
	private static final Logger logger = LogManager.getLogger(PatchFinder.class.getName());
	private final PatchFinder patchFinder;

	/**
	 * Thread object used for multithreaded patchfinding
	 * @param cvePatchEntry
	 * @param clonePath
	 */
	public PatchFinderThread(HashMap<String, ArrayList<String>> cvePatchEntry, String clonePath, PatchFinder patchFinder) {
		this.cvePatchEntry = cvePatchEntry;
		this.clonePath = clonePath;
		this.patchFinder = patchFinder;
	}

	/**
	 * Used for cloning, crawling, and deleting product repos to find patch commits
	 */
	@Override
	public void run() {

		ArrayList<PatchCommit> foundPatchCommits = new ArrayList<>();
		// For each CVE, iterate through the list of possible patch sources and
		// Clone/Scrape the repo for patch commits (if any)
		for (String cve : cvePatchEntry.keySet()) {
			for (String patchSource: cvePatchEntry.get(cve)) {
				try {
					// Clone git repo
					GitController gitController = new GitController(clonePath + "/" + cve, patchSource+".git");
					gitController.cloneRepo();

					// Find patch commits
					PatchCommitScraper commitScraper = new PatchCommitScraper(clonePath + "/" + cve, patchSource);
					List<PatchCommit> patchCommits = commitScraper.parseCommits(cve);
					foundPatchCommits.addAll(patchCommits);

					// Delete repo when done
					gitController.deleteRepo();
				} catch (Exception e) {
					logger.error("ERROR: Failed to find patch from source {} for CVE {}\n{}", patchSource, cve, e.toString());
				}
			}
		}

		// Add found commits to total list after finished
		this.patchFinder.getPatchCommits().addAll(foundPatchCommits);
	}
}
