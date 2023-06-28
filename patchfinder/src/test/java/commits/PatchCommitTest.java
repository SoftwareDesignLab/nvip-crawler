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
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;


public class PatchCommitTest {

    @Test
    public void testPatchCommit() {
        String commitURL = "https://example.com/commit";
        String cveId = "CVE-2023-1234";
        String commitId = "abc123";
        Date commitDate = new Date();
        String commitMessage = "Fix a security vulnerability";
        String uniDiff = "diff --git a/file.txt b/file.txt";
        List<RevCommit> timeline = new ArrayList<>();
        String timeToPatch = "5 days";
        int linesChanged = 10;

        PatchCommit patchCommit = new PatchCommit(commitURL, cveId, commitId, commitDate, commitMessage, uniDiff, timeline, timeToPatch, linesChanged);

        // Verify the values returned by the getter methods
        assertEquals(commitURL, patchCommit.getCommitURL());
        assertEquals(cveId, patchCommit.getCveId());
        assertEquals(commitId, patchCommit.getCommitId());
        assertEquals(commitDate, patchCommit.getCommitDate());
        assertEquals(commitURL, patchCommit.getCommitUrl());
        assertEquals(commitMessage, patchCommit.getCommitMessage());
        assertEquals(uniDiff, patchCommit.getUniDiff());
        assertEquals(timeline, patchCommit.getTimeline());
        assertEquals(timeToPatch, patchCommit.getTimeToPatch());
        assertEquals(linesChanged, patchCommit.getLinesChanged());
    }
}