import commits.PatchCommit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static com.helger.commons.mock.CommonsAssert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PatchFinderThreadTest {

    @Test
    public void testRun() {
        HashMap<String, ArrayList<String>> cvePatchEntry = new HashMap<>();
        ArrayList<String> patchSources = new ArrayList<>();
        patchSources.add("https://github.com/apache/airflow");
        cvePatchEntry.put("CVE-2023-1001", patchSources);
        String clonePath = "clonePath";
        long timeoutMilli = 5000;

        PatchFinderThread patchFinderThread = new PatchFinderThread(cvePatchEntry, clonePath, timeoutMilli);
        patchFinderThread.run();

        PatchFinder patchFinder = Mockito.mock(PatchFinder.class);
        //check the patch commits
        List<PatchCommit> patchCommits = patchFinder.getPatchCommits();
        assertEquals(23, patchCommits.size());

    }
}