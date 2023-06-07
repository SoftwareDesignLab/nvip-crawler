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

import org.eclipse.jgit.revwalk.RevCommit;
import org.joda.time.DateTime;

import java.time.LocalDateTime;

/**
 * Model class for patchcommits found by patchfinder
 */
public class PatchCommit {
	private final String commitURL;
	private final String cveId;
	private LocalDateTime commitDate;

	public PatchCommit(String commitURL, String cveId, LocalDateTime commitDate) {
		this.cveId = cveId;
		this.commitURL = commitURL;
		this.commitDate = commitDate;
	}

	public String getCommitUrl() {
		return this.commitURL;
	}

	public String getCveId() { return this.cveId; }

	public LocalDateTime getCommitDate() {return this.commitDate; }
}
