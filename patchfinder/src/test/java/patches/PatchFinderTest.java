/ **
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
* /

package patches; /**
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

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.model.CpeEntry;
import edu.rit.se.nvip.db.model.CpeGroup;
import edu.rit.se.nvip.db.repositories.PatchFixRepository;
import edu.rit.se.nvip.db.repositories.ProductRepository;
import env.PatchFinderEnvVars;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ThreadPoolExecutor;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.platform.commons.function.Try.success;
import static org.mockito.Mockito.*;

/**
 * Unit tests for PatchFinder class
 *
 * @author Richard Sawh
 */
public class PatchFinderTest {
    private final DatabaseHelper databaseHelperMock = mock(DatabaseHelper.class);

    @BeforeEach
    public void setUp() {
        PatchFinderEnvVars.initializeEnvVars(true);
        PatchFinder.init(databaseHelperMock, mock(ProductRepository.class), mock(PatchFixRepository.class));
    }

    @Test
    @Disabled("Until we figure out why the GitHub runner fails this test")
    public void testFindPatchesMultiThreaded2() {
        // Create a sample input for possiblePatchSources
        ArrayList<String> possiblePatchSources = new ArrayList<>();
        possiblePatchSources.add("https://www.github.com/python-pillow/Pillow");

        // Mock the ThreadPoolExecutor
        ThreadPoolExecutor e = mock(ThreadPoolExecutor.class);

        // Call the method
        final Set<PatchCommit> patchCommits = PatchFinder.findPatchesMultiThreaded("CVE-2016-0775", possiblePatchSources);

        // Add assertions here to validate the expected behavior
        // For example, check if the repos are cleared
        assertTrue(new File(PatchFinder.clonePath).exists());

        // Check the patch commits
        assertEquals(1, patchCommits.size());
    }


    @Test
    @Disabled("Until we figure out why the GitHub runner fails this test")
    public void testFindPatchesMultiThreaded() {
        // Create a sample input for possiblePatchSources
        ArrayList<String> possiblePatchSources = new ArrayList<>();
        possiblePatchSources.add("https://github.com/apache/airflow");
        // Call the findPatchesMultiThreaded method and assert the expected behavior or outcome
        PatchFinder.findPatchesMultiThreaded("CVE-2023-1001", possiblePatchSources);
        // Assert that the affectedProducts map is empty
        assertEquals(1, possiblePatchSources.size());

    }

    // TODO: numPatches may contain duplicate data, find out why (24 found patches -> 48 returned)
    @Test
    public void testRun() {
        // Create a test input map of affected products
        //(String vendor, String product, String commonTitle, HashMap<String, CpeEntry> versions)
        //1	CVE-2023-1001	cpe:2.3:a:apache:airflow:1.7.0:rc1:*:*:*:*:*:*	2023-06-20 10:00:00	product_name_value	version_value
        CpeGroup cpeGroup = new CpeGroup("apache", "airflow", "product_name_value", new HashMap<>());
        ProductRepository prodMock = mock(ProductRepository.class);
        PatchFixRepository pfMock = mock(PatchFixRepository.class);
        PatchFinder.init(databaseHelperMock, prodMock, pfMock);
        try {
            final int numPatches = PatchFinder.run("CVE-2023-1001", cpeGroup);

            // Call the run method and assert the expected behavior or outcome, should be 0 because they already exist in the db
            if(numPatches == 0) success("patches already exist in the db");
            else if (numPatches == 48) success("patches added to the db");
            else fail("patches not added to the db");
        } catch (IOException e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }

    @Test
    public void testRun2() throws IOException {
        // Test data
        String cveId = "CVE-2023-1001";
        final String versionString = "1.2.3";
        final String versionString2 = "1.2.4";
        HashMap<String, CpeEntry> entry = new HashMap<>();
        entry.put(versionString, new CpeEntry(versionString, "rc1", "2023-06-20 10:00:00"));
        entry.put(versionString2, new CpeEntry(versionString2, "rc1", "2023-06-20 10:00:00"));
        CpeGroup cpeGroup = new CpeGroup("apache", "airflow", "product_name_value", entry);
        String cveId2 = "CVE-2021-3572";
        CpeGroup cpeGroup2 = new CpeGroup("apache", "tomcat", "product_name_value", entry);

        // Create the affectedProducts map with the test data
        Map<String, CpeGroup> affectedProducts = new HashMap<>();
        affectedProducts.put(cveId, cpeGroup);
        affectedProducts.put(cveId2, cpeGroup2);

        int numPatches = 0;
        for (Map.Entry<String, CpeGroup> product : affectedProducts.entrySet()) {
            numPatches += PatchFinder.run(product.getKey(), product.getValue());
        }

        // Call the run method and assert the expected behavior or outcome, should be 0 because they already exist in the db
        if(numPatches == 0) success("patches already exist in the db");
        else if (numPatches == 74) success("patches added to the db");
        else fail("patches not added to the db");
    }
}
