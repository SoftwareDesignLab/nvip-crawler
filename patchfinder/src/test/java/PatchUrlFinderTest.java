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

import model.CpeEntry;
import model.CpeGroup;
import org.junit.jupiter.api.Assertions;
import org.junit.Test;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Unit tests for PatchUrlFinder class
 *
 * @author Richard Sawh
 */
public class PatchUrlFinderTest {

    @Test
    public void testParseMassURLs() {
        // Create a test instance of PatchUrlFinder
        PatchUrlFinder patchUrlFinder = new PatchUrlFinder();

        // Create test data
        Map<String, CpeGroup> affectedProducts = new HashMap<>();

        //add version to the hashmap,put "version_value" for now
        HashMap<String, CpeEntry> version = new HashMap<>();
        version.put("1.0.0", new CpeEntry("Entry 1", "1.0.0", "Update 1", "cpeID1", "Platform 1"));
        version.put("2.0.0", new CpeEntry("Entry 2", "2.0.0", "Update 2", "cpeID2", "Platform 2"));
        version.put("3.0.0", new CpeEntry("Entry 3", "3.0.0", "Update 3", "cpeID3", "Platform 3"));


        // Create an instance of CpeGroup for the first affected product
        CpeGroup cpeGroup1 = new CpeGroup("apache", "airflow", "Apache Airflow", version);
        // Set any other necessary properties of the CpeGroup

        // Add the first affected product to the map
        affectedProducts.put("CVE-2023-1001", cpeGroup1);

        // Create an instance of CpeGroup for the second affected product
        CpeGroup cpeGroup2 = new CpeGroup("apache", "apache", "Apache Tomcat", version);
        // Set any other necessary properties of the CpeGroup

        // Add the second affected product to the map
        affectedProducts.put("CVE-2021-3572", cpeGroup2);

        int cveLimit = 10; // Set the desired CVE limit for testing

        // Invoke the method being tested
        Map<String, ArrayList<String>> cveCpeUrls = new HashMap<>();
        patchUrlFinder.parsePatchURLs(cveCpeUrls, affectedProducts, cveLimit, true);

        // Perform assertions to check the results
        Assertions.assertNotNull(cveCpeUrls);
        // Add more assertions as needed
    }

    @Test
    public void testSearchForRepos() {
        // Create a test instance of PatchUrlFinder
        PatchUrlFinder patchUrlFinder = new PatchUrlFinder();

        // Create test data
        Map<String, CpeGroup> affectedProducts = new HashMap<>();

        //add version to the hashmap,put "version_value" for now
        HashMap<String, CpeEntry> version = new HashMap<>();
        version.put("1.0.0", new CpeEntry("Entry 1", "1.0.0", "Update 1", "cpeID1", "Platform 1"));
        version.put("2.0.0", new CpeEntry("Entry 2", "2.0.0", "Update 2", "cpeID2", "Platform 2"));
        version.put("3.0.0", new CpeEntry("Entry 3", "3.0.0", "Update 3", "cpeID3", "Platform 3"));



        // Create an instance of CpeGroup for the first affected product
        CpeGroup cpeGroup1 = new CpeGroup("apache", "airflow", "Apache Airflow", version);
        // Set any other necessary properties of the CpeGroup

        // Add the first affected product to the map
        affectedProducts.put("CVE-2023-1001", cpeGroup1);

        // Create an instance of CpeGroup for the second affected product
        CpeGroup cpeGroup2 = new CpeGroup("apache", "", "", version);
        // Set any other necessary properties of the CpeGroup

        // Add the second affected product to the map
        affectedProducts.put("CVE-2021-3572", cpeGroup2);

        int cveLimit = 5; // Set the desired CVE limit for testing

        // Invoke the method being tested
        Map<String, ArrayList<String>> cveCpeUrls = new HashMap<>();
        patchUrlFinder.parsePatchURLs(cveCpeUrls, affectedProducts, cveLimit, true);

        // Perform assertions to check the results
        Assertions.assertNotNull(cveCpeUrls);
        // Add more assertions as needed
    }

}