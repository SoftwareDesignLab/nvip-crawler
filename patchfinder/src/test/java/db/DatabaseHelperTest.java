package db;

import model.CpeGroup;
import org.eclipse.jgit.revwalk.RevCommit;
import org.junit.Before;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import org.junit.Test;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.platform.commons.function.Try.success;

public class DatabaseHelperTest {
    private static final String DATABASE_TYPE = System.getenv("DB_TYPE");
    private static final String HIKARI_URL = System.getenv("HIKARI_URL");
    private static final String HIKARI_USER = System.getenv("HIKARI_USER");
    private static final String HIKARI_PASSWORD = System.getenv("HIKARI_PASSWORD");
    private static final String TEST_CVE_ID = "CVE-2023-1001";


    private static DatabaseHelper databaseHelper;

    @Before
    public void setUp() {
        databaseHelper = new DatabaseHelper(DATABASE_TYPE, HIKARI_URL, HIKARI_USER, HIKARI_PASSWORD);
    }

    @AfterAll
    public static void tearDown() {
        databaseHelper.shutdown();
    }

    @Test
    public void testGetAffectedProducts() {
        Map<String, CpeGroup> affectedProducts = databaseHelper.getAffectedProducts(null);
        assertNotNull(affectedProducts);
        assertFalse(affectedProducts.isEmpty());
        assertTrue(affectedProducts.containsKey(TEST_CVE_ID));
        // Add more assertions to verify the correctness of the returned affected products
    }

    @Test
    public void testInsertPatchSourceURL() {
        String sourceURL = "https://example.com";
        int sourceId = databaseHelper.insertPatchSourceURL(new HashMap<>(), TEST_CVE_ID, sourceURL);
        assertTrue(sourceId > 0);
    }

    @Test
    public void testInsertPatchCommit() {
        int sourceId = 1; // Assume a valid source ID
        String patchCommitSha = "abcdef123456";
        String cveId = "CVE-2023-3765";
        java.util.Date commitDate = new java.util.Date();
        String commitMessage = "Fix vulnerability";
        String uniDiff = "diff --git a/file1 b/file1\n+++ b/file1\n@@ -1,3 +1,3 @@\n-line1\n-line2\n+line3\n+line4";
        List<RevCommit> timeLine = new ArrayList<>(); // Assume a valid timeline
        String timeToPatch = "2 days";
        int linesChanged = 2;

        // Insert the patch commit
        databaseHelper.insertPatchCommit(sourceId, cveId, patchCommitSha, commitDate, commitMessage, uniDiff, timeLine, timeToPatch, linesChanged);

        // Verify the insertion by checking if the commit URL exists in the database
        Set<String> existingCommitShas = databaseHelper.getExistingPatchCommitShas();
        assertTrue(existingCommitShas.contains(patchCommitSha));
    }

    @Test
    public void testInsertPatchCommitWithDuplicates() {
        // Prepare test data
        int sourceId = 1; // Assume a valid source ID
        String patchCommitSha = "abcdef123456";
        String cveId = "CVE-2023-3765";
        java.util.Date commitDate = new java.util.Date();
        String commitMessage = "Fix vulnerability";
        String uniDiff = "diff --git a/file1 b/file1\n+++ b/file1\n@@ -1,3 +1,3 @@\n-line1\n-line2\n+line3\n+line4";
        List<RevCommit> timeLine = new ArrayList<>(); // Assume a valid timeline
        String timeToPatch = "2 days";
        int linesChanged = 2;

        // Insert the first patch commit
        databaseHelper.insertPatchCommit(sourceId, cveId, patchCommitSha, commitDate, commitMessage, uniDiff, timeLine, timeToPatch, linesChanged);

        // Attempt to insert the same patch commit again
        try {
            databaseHelper.insertPatchCommit(sourceId, cveId, patchCommitSha, commitDate, commitMessage, uniDiff, timeLine, timeToPatch, linesChanged);
            success("Expected IllegalArgumentException to be thrown due to duplicate patch commit");
        } catch (IllegalArgumentException e) {
            // The exception is expected to be thrown
            // Add assertions or verify the exception message, if needed
            String expectedErrorMessage = "Failed to insert patch commit, as it already exists in the database";
            assertEquals(expectedErrorMessage, e.getMessage());
        }
    }

}

