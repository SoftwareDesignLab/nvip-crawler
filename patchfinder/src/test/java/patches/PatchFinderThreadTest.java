package patches; /**
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

import org.junit.Ignore;
import patches.PatchCommit;
import org.junit.Test;
import org.mockito.Mockito;
import patches.PatchFinder;
import patches.PatchFinderThread;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for PatchFinderThread class
 *
 * @author Richard Sawh
 */
public class PatchFinderThreadTest {

    //TODO: This needs to be re-written to utilize mocks. This test was failing because the apache airflow github added more patch commits
    @Test
    @Ignore
    public void testRun() {
        HashMap<String, ArrayList<String>> cvePatchEntry = new HashMap<>();
        ArrayList<String> patchSources = new ArrayList<>();
        patchSources.add("https://github.com/apache/airflow");
        cvePatchEntry.put("CVE-2023-1001", patchSources);
        String clonePath = PatchFinder.clonePath;
        long timeoutMilli = 5000;

        PatchFinderThread patchFinderThread = new PatchFinderThread(cvePatchEntry, clonePath, timeoutMilli);
        patchFinderThread.run();

        PatchFinder patchFinder = Mockito.mock(PatchFinder.class);
        //check the patch commits
        Set<PatchCommit> patchCommits = PatchFinder.getPatchCommits();
        assertEquals(24, patchCommits.size());
    }

    //Cant find a repo to test this with that matches the >1000 commits threshold
    @Test
    public void testFindPatchCommitsFromUrl() {
        HashMap<String, ArrayList<String>> cvePatchEntry = new HashMap<>();
        //clear patchcommits
        PatchFinder.getPatchCommits().clear();
        ArrayList<String> patchSources = new ArrayList<>();
        patchSources.add("https://github.com/OpenCycleCompass/server-php");
        cvePatchEntry.put("CVE-2015-10086", patchSources);
        String clonePath = PatchFinder.clonePath;
        long timeoutMilli = 5000;

        PatchFinderThread patchFinderThread = new PatchFinderThread(cvePatchEntry, clonePath, timeoutMilli);
        patchFinderThread.run();

        PatchFinder patchFinder = Mockito.mock(PatchFinder.class);
        //check the patch commits
        Set<PatchCommit> patchCommits = PatchFinder.getPatchCommits();
        assertEquals(0, patchCommits.size());

    }

    @Test
    public void testParseCommitObjects() throws IOException {
        HashMap<String, ArrayList<String>> cvePatchEntry = new HashMap<>();
        ArrayList<String> patchSources = new ArrayList<>();
        patchSources.add("https://github.com/kkent030315/CVE-2022-42046");
        cvePatchEntry.put("CVE-2022-42046", patchSources);
//        String clonePath = PatchFinder.clonePath;
//        long timeoutMilli = 5000;
        //clear patchcommits
        PatchFinder.getPatchCommits().clear();
        //want parseCommitObjects to be called, so we have to check the url using findPatchCommitsFromUrl
        PatchFinder.findPatchesMultiThreaded(cvePatchEntry);
        Set<PatchCommit> patchCommits = PatchFinder.getPatchCommits();
        assertEquals(0, patchCommits.size());

    }

}