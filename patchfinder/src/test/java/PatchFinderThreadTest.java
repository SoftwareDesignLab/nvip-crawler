import commits.PatchCommit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.Assert.assertTrue;

public class PatchFinderThreadTest {

    @Test
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
        List<PatchCommit> patchCommits = PatchFinder.getPatchCommits();
        assertEquals(24, patchCommits.size());

    }

    //Cant find a repo to test this with that matches the >1000 commits threshold
    @Test
    public void testFindPatchCommitsFromUrl() {
        HashMap<String, ArrayList<String>> cvePatchEntry = new HashMap<>();
        ArrayList<String> patchSources = new ArrayList<>();
        patchSources.add("https://github.com/OpenCycleCompass/server-php");
        cvePatchEntry.put("CVE-2015-10086", patchSources);
        String clonePath = PatchFinder.clonePath;
        long timeoutMilli = 5000;

        PatchFinderThread patchFinderThread = new PatchFinderThread(cvePatchEntry, clonePath, timeoutMilli);
        patchFinderThread.run();

        PatchFinder patchFinder = Mockito.mock(PatchFinder.class);
        //check the patch commits
        List<PatchCommit> patchCommits = PatchFinder.getPatchCommits();
        assertEquals(24, patchCommits.size());

    }

    @Test
    public void testParseCommitObjects() throws IOException {
        HashMap<String, ArrayList<String>> cvePatchEntry = new HashMap<>();
        ArrayList<String> patchSources = new ArrayList<>();
        patchSources.add("https://github.com/pjsip/pjproject");
        cvePatchEntry.put("CVE-2022-31031", patchSources);
//        String clonePath = PatchFinder.clonePath;
//        long timeoutMilli = 5000;

        //want parseCommitObjects to be called, so we have to check the url using findPatchCommitsFromUrl
        PatchFinder.cloneCommitThreshold = 7000;
        PatchFinder.findPatchesMultiThreaded(cvePatchEntry);
        List<PatchCommit> patchCommits = PatchFinder.getPatchCommits();
        assertEquals(24, patchCommits.size());

    }

}