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
import java.util.Date;
import java.util.List;

/**
 * Model class for patchcommits found by patchfinder
 */
public class PatchCommit {
	private final String commitURL;
	private final String cveId;
	private final String commitId;
	private final Date commitDate;
	private final String commitMessage;
	private final String uniDiff;
	private List<RevCommit> timeline;
	private long timeToPatch;
	private int linesChanged;

	/**
	 * Model class for patch commit objects
	 *
	 * @param commitURL     the URL of the commit
	 * @param cveId         the CVE ID associated with the patch commit
	 * @param commitId      the ID of the commit
	 * @param commitDate    the date of the commit
	 * @param commitMessage the commit message
	 * @param uniDiff       the unified diff of the commit
	 */
	public PatchCommit(String commitURL, String cveId, String commitId, Date commitDate, String commitMessage, String uniDiff) {
		this.commitURL = commitURL;
		this.cveId = cveId;
		this.commitId = commitId;
		this.commitDate = commitDate;
		this.commitMessage = commitMessage;
		this.uniDiff = uniDiff;
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

	public Date getCommitDate() {
		return commitDate;
	}

	public String getCommitUrl() {
		return commitURL;
	}

	public String getCommitMessage() {
		return commitMessage;
	}

	public String getUniDiff() {
		return uniDiff;
	}

	public List<RevCommit> getTimeline() {
		return timeline;
	}

	public void setTimeline(List<RevCommit> timeline) {
		this.timeline = timeline;
	}

	public long getTimeToPatch() {
		return timeToPatch;
	}

	public void setTimeToPatch(long timeToPatch) {
		this.timeToPatch = timeToPatch;
	}

	public int getLinesChanged() {
		return linesChanged;
	}

	public void setLinesChanged(int linesChanged) {
		this.linesChanged = linesChanged;
	}
}