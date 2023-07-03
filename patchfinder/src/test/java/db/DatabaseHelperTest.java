package db;

import model.CpeGroup;
import org.eclipse.jgit.revwalk.RevCommit;
import org.junit.jupiter.api.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class DatabaseHelperTest {
    private static final String DATABASE_TYPE = System.getenv("DB_TYPE");
    private static final String HIKARI_URL = System.getenv("HIKARI_URL");
    private static final String HIKARI_USER = System.getenv("HIKARI_USER");
    private static final String HIKARI_PASSWORD = System.getenv("HIKARI_PASSWORD");
    private static final String TEST_CVE_ID = "CVE-2023-1001";


    private static DatabaseHelper databaseHelper;

    @BeforeAll
    public static void setUp() {
        databaseHelper = new DatabaseHelper(DATABASE_TYPE, HIKARI_URL, HIKARI_USER, HIKARI_PASSWORD);
    }

    @AfterAll
    public static void tearDown() {
        databaseHelper.shutdown();
    }

    @Test
    public void testGetAffectedProducts() {
        Map<String, CpeGroup> affectedProducts = databaseHelper.getAffectedProducts();
        assertNotNull(affectedProducts);
        assertFalse(affectedProducts.isEmpty());
        assertTrue(affectedProducts.containsKey(TEST_CVE_ID));
        // Add more assertions to verify the correctness of the returned affected products
    }

    @Test
    public void testGetVulnIdByCveId() {
        int vulnId = databaseHelper.getVulnIdByCveId(TEST_CVE_ID);
        // Add assertions to verify the correctness of the returned vulnId
    }

    @Test
    public void testInsertPatchSourceURL() {
        String sourceURL = "https://example.com";
        int sourceId = databaseHelper.insertPatchSourceURL(new HashSet<>(), TEST_CVE_ID, sourceURL);
        // Add assertions to verify the correctness of the inserted patch source URL
    }

    @Test
    public void testInsertPatchCommit() {
        int sourceId = 1; // Assume a valid source ID
        String sourceURL = "https://example.com/commit/abcdef123456";
        java.util.Date commitDate = new java.util.Date();
        String commitMessage = "Fix vulnerability";
        String uniDiff = "diff --git a/file1 b/file1\n+++ b/file1\n@@ -1,3 +1,3 @@\n-line1\n-line2\n+line3\n+line4";
        List<RevCommit> timeLine = new ArrayList<>(); // Assume a valid timeline
        String timeToPatch = "2 days";
        int linesChanged = 2;

        databaseHelper.insertPatchCommit(sourceId, sourceURL, commitDate, commitMessage, uniDiff, timeLine, timeToPatch, linesChanged);
        // Add assertions or verify the insertion in the database
    }
}

