/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

package patches;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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
	private List<String> timeline;
	private String timeToPatch;
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
	public PatchCommit(String commitURL, String cveId, String commitId, Date commitDate, String commitMessage, String uniDiff, List<String> timeline, String timeToPatch, int linesChanged) {
		super();
		this.commitURL = commitURL;
		this.cveId = cveId;
		this.commitId = commitId;
		this.commitDate = commitDate; // TODO: Truncating time?
		this.commitMessage = commitMessage;
		this.uniDiff = uniDiff;
		this.timeline = timeline;
		this.timeToPatch = timeToPatch;
		this.linesChanged = linesChanged;
	}

	/** Get function for a patch paramater
	 *
	 * @return the commitURL of the patch
	 */
	public String getCommitURL() {return commitURL;}
	/** Get function for a patch paramater
	 *
	 * @return the cveID for the patch
	 */
	public String getCveId() {return cveId;}
	/** Get function for a patch paramater
	 *
	 * @return the commitId of the patch
	 */
	public String getCommitId() {return commitId;}
	/** Get function for a patch paramater
	 *
	 * @return the commitDate of the patch
	 */
	public Date getCommitDate() {return commitDate;}
	/** Get function for a patch paramater
	 *
	 * @return the commitURL of the patch
	 */
	public String getCommitUrl() {return commitURL;}
	/** Get function for a patch paramater
	 *
	 * @return the commitMessage of the patch
	 */
	public String getCommitMessage() {return commitMessage;}
	/** Get function for a patch paramater
	 *
	 * @return the uniDiff of the patch
	 */
	public String getUniDiff() {return uniDiff;}
	/** Get function for a patch paramater
	 *
	 * @return the timeline of the patch
	 */
	public List<String> getTimeline() {return timeline;}

	/**Set function for patch parameter
	 *
	 * @param timeline the timeline to set for the patch
	 */
	public void setTimeline(List<String> timeline) {this.timeline = timeline;}
	/** Get function for a patch paramater
	 *
	 * @return the timeToPatch of the patch
	 */
	public String getTimeToPatch() {return timeToPatch;}

	/**Set function for a patch parameter
	 *
	 * @param timeToPatch string to set patch parameter to
	 */
	public void setTimeToPatch(String timeToPatch) {this.timeToPatch = timeToPatch;}
	/** Get function for a patch paramater
	 *
	 * @return the linesChanged of the patch
	 */
	public int getLinesChanged() {return linesChanged;}
	/** Set function for a patch paramater
	 *
	 * @param linesChanged int to set lineschanged parameter of patch to
	 */
	public void setLinesChanged(int linesChanged) {this.linesChanged = linesChanged;}


}