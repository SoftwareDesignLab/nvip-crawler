import model.CpeGroup;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ThreadPoolExecutor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class PatchFinderTest {

    @Test
    public void testFindPatchesMultiThreaded() {
        // Create a sample input for possiblePatchSources
        Map<String, ArrayList<String>> possiblePatchSources = new HashMap<>();
        ArrayList<String> patchSources1 = new ArrayList<>();
        patchSources1.add("https://github.com/apache/airflow");
        possiblePatchSources.put("CVE-2023-1001", patchSources1);
        ThreadPoolExecutor e = mock(ThreadPoolExecutor.class);

        //clear the patch commits
        PatchFinder.getPatchCommits().clear();
        // Call the method
        PatchFinder.findPatchesMultiThreaded(possiblePatchSources);

        // Add assertions here to validate the expected behavior
        // For example, check if the repos are cleared
        assertTrue(new File(PatchFinder.clonePath).exists());

        //check the patch commits
        assertEquals(24, PatchFinder.getPatchCommits().size());

        // Add more assertions based on your requirements
    }

    @Test
    public void testFetchEnvVars() {
        PatchFinder.fetchEnvVars();

        // Assert that the properties have been set correctly
        assertEquals(20, PatchFinder.cveLimit);
        assertEquals(10, PatchFinder.maxThreads);
        assertEquals(1, PatchFinder.cvesPerThread);
        assertEquals("patchfinder/src/main/resources/patch-repos", PatchFinder.clonePath);
        assertEquals("mysql", PatchFinder.databaseType);
        assertEquals(2000, PatchFinder.cloneCommitThreshold);
    }

    @Test
    public void testRun() {
        // Create a test input map of affected products
        Map<String, CpeGroup> possiblePatchSources = new HashMap<>();
        //(String vendor, String product, String commonTitle, HashMap<String, CpeEntry> versions)
        //1	CVE-2023-1001	cpe:2.3:a:apache:airflow:1.7.0:rc1:*:*:*:*:*:*	2023-06-20 10:00:00	product_name_value	version_value
        CpeGroup cpeGroup = new CpeGroup("apache", "airflow", "product_name_value", new HashMap<>());
        possiblePatchSources.put("CVE-2023-1001", cpeGroup);

        PatchFinder.init();
        try {
            // Call the run method and assert the expected behavior or outcome
            PatchFinder.run(possiblePatchSources, PatchFinder.cveLimit);

            // Assert that the affectedProducts map is empty
            assertEquals(1, possiblePatchSources.size());
        } catch (IOException e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }


}
