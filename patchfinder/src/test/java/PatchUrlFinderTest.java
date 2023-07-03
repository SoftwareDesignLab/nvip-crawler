import model.CpeGroup;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class PatchUrlFinderTest {

    @Test
    public void testParseMassURLs() throws IOException, InterruptedException {
        // Create a test instance of PatchUrlFinder
        PatchUrlFinder patchUrlFinder = new PatchUrlFinder();

        // Create test data
        Map<String, CpeGroup> affectedProducts = new HashMap<>();

        // Create an instance of CpeGroup for the first affected product
        CpeGroup cpeGroup1 = new CpeGroup("apache", "airflow", "Apache Airflow", new HashMap<>());
        // Set any other necessary properties of the CpeGroup

        // Add the first affected product to the map
        affectedProducts.put("CVE-2023-1001", cpeGroup1);

        // Create an instance of CpeGroup for the second affected product
        CpeGroup cpeGroup2 = new CpeGroup("apache", "apache", "Apache Tomcat", new HashMap<>());
        // Set any other necessary properties of the CpeGroup

        // Add the second affected product to the map
        affectedProducts.put("CVE-2021-3572", cpeGroup2);

        int cveLimit = 5; // Set the desired CVE limit for testing

        // Invoke the method being tested
        Map<String, ArrayList<String>> cveCpeUrls = new HashMap<>();
        patchUrlFinder.parseMassURLs(cveCpeUrls, affectedProducts, cveLimit);

        // Perform assertions to check the results
        Assertions.assertNotNull(cveCpeUrls);
        // Add more assertions as needed
    }

    @Test
    public void testSearchForRepos() throws IOException, InterruptedException {
        // Create a test instance of PatchUrlFinder
        PatchUrlFinder patchUrlFinder = new PatchUrlFinder();

        // Create test data
        Map<String, CpeGroup> affectedProducts = new HashMap<>();

        // Create an instance of CpeGroup for the first affected product
        CpeGroup cpeGroup1 = new CpeGroup("apache", "airflow", "Apache Airflow", new HashMap<>());
        // Set any other necessary properties of the CpeGroup

        // Add the first affected product to the map
        affectedProducts.put("CVE-2023-1001", cpeGroup1);

        // Create an instance of CpeGroup for the second affected product
        CpeGroup cpeGroup2 = new CpeGroup("apache", "", "", new HashMap<>());
        // Set any other necessary properties of the CpeGroup

        // Add the second affected product to the map
        affectedProducts.put("CVE-2021-3572", cpeGroup2);

        int cveLimit = 5; // Set the desired CVE limit for testing

        // Invoke the method being tested
        Map<String, ArrayList<String>> cveCpeUrls = new HashMap<>();
        patchUrlFinder.parseMassURLs(cveCpeUrls, affectedProducts, cveLimit);

        // Perform assertions to check the results
        Assertions.assertNotNull(cveCpeUrls);
        // Add more assertions as needed
    }



}