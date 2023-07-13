import db.DatabaseHelper;
import model.CpeEntry;
import model.CpeGroup;
import org.junit.Test;
import org.mockito.Mockito;

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

        try {
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
        } catch (IOException e1) {
            fail("Exception thrown: " + e1.getMessage());
        }
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
        Map<String, CpeGroup> affectedProducts = new HashMap<>();
        // Add test data to the affectedProducts map
        // Create a CpeGroup object
        CpeGroup cpeGroup = new CpeGroup("apache", "airflow", "airflow", new HashMap<>());
        affectedProducts.put("CVE-2023-1001", cpeGroup);
        PatchFinder.init();
        try {
            // Call the run method and assert the expected behavior or outcome
            PatchFinder.run(affectedProducts);

            // Assert that the affectedProducts map is empty
            assertEquals(1, affectedProducts.size());
        } catch (IOException | InterruptedException e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }


}
