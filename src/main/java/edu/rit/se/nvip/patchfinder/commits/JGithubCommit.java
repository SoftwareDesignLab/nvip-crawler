/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
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

import java.util.List;

import org.eclipse.jgit.revwalk.RevCommit;

/**
 *
 * @author Fawaz Alhenaki <faa5019@rit.edu>
 */
public class JGithubCommit {

	private final String sha;
	private final List<String> foundBugs;
	private final List<String> foundCves;
	private final List<String> foundVulns;
	private final RevCommit commit;
	private final List<String> affectedFiles;

	public JGithubCommit(String sha, List<String> foundCves, List<String> foundBugs, List<String> foundVulns,
			RevCommit commit, List<String> affectedFiles) {
		this.sha = sha;
		this.foundCves = foundCves;
		this.foundBugs = foundBugs;
		this.foundVulns = foundVulns;
		this.commit = commit;
		this.affectedFiles = affectedFiles;
	}

	public List<String> getFoundBugs() {
		return foundBugs;
	}

	public List<String> getFoundCves() {
		return foundCves;
	}

	public List<String> getFoundVulns() {
		return foundVulns;
	}

	public RevCommit getCommit() {
		return commit;
	}

	public boolean isFixingCve() {
		return this.foundCves.size() > 0;
	}

	public boolean isFixingBug() {
		return this.foundBugs.size() > 0;
	}

	public boolean isFixingVuln() {
		return this.foundVulns.size() > 0;
	}

	public List<String> getAffectedFiles() {
		return this.affectedFiles;
	}

	public String getSha() {
		return sha;
	}
}
