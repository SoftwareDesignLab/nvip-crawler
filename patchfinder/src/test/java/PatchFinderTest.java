import model.CpeGroup;
import org.junit.Ignore;
import org.junit.Test;
import utils.GitController;

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
        // Call the findPatchesMultiThreaded method and assert the expected behavior or outcome
        PatchFinder.findPatchesMultiThreaded(possiblePatchSources);
        // Assert that the affectedProducts map is empty
        assertEquals(1, possiblePatchSources.size());

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
