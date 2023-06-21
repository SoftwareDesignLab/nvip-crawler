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


import org.eclipse.jgit.revwalk.RevCommit;
import org.joda.time.DateTime;


import java.time.Instant;
import java.time.LocalDateTime;


/**
 * Model class for patchcommits found by patchfinder
 */
public class PatchCommit {
	private final String commitURL;
	private final String cveId;
	private final String commitId;
	private long commitDate;
	private final String commitMessage;
	private final String unifiedDiff;


	/**
	 * Model class for patch commit objects
	 * @param commitURL
	 * @param cveId
	 * @param commitId
	 * @param commitDate
	 * @param commitMessage
	 * @param unifiedDiff
	 */
	public PatchCommit(String commitURL, String cveId, String commitId, long commitDate, String commitMessage, String unifiedDiff) {
		this.commitURL = commitURL;
		this.cveId = cveId;
		this.commitId = commitId;
		this.commitDate = commitDate;
		this.commitMessage = commitMessage;
		this.unifiedDiff = unifiedDiff;
	}


	public String getCommitURL() {
		return commitURL;
	}


	public String getCveId() {
		return cveId;
	}


	public String getCommitId() {
		return commitId;
	}


	public long getCommitDate() {
		return commitDate;
	}


	public String getCommitUrl() {
		return this.commitURL;
	}


	public String getCommitMessage() {
		return commitMessage;
	}


	public String getUnifiedDiff() {
		return unifiedDiff;
	}
}
