package edu.rit.se.nvip.db.repositories;

import org.junit.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class PatchFixRepositoryTest {
    // todo update these tests


//    @Test
//    public void testInsertPatchSourceURL() {
//        String sourceURL = "https://example.com";
//        int sourceId = databaseHelper.insertPatchSourceURL(new HashMap<>(), TEST_CVE_ID, sourceURL);
//        assertFalse(sourceId >= 0);
//    }
//
//    @Test
//    public void testInsertPatchCommit() {
//        // Mock the databaseHelper
//        DatabaseHelper databaseHelper = mock(DatabaseHelper.class);
//
//        int sourceId = 1; // Assume a valid source ID
//        String patchCommitSha = "abcdef123456";
//        String cveId = "CVE-2023-3765";
//        java.util.Date commitDate = new java.util.Date();
//        String commitMessage = "Fix vulnerability";
//        String uniDiff = "diff --git a/file1 b/file1\n+++ b/file1\n@@ -1,3 +1,3 @@\n-line1\n-line2\n+line3\n+line4";
//        List<String> timeLine = new ArrayList<>(); // Assume a valid timeline
//        String timeToPatch = "2 days";
//        int linesChanged = 2;
//
//        // Insert the patch commit (Assuming your databaseHelper has the appropriate method signature)
//        databaseHelper.insertPatchCommit(sourceId, cveId, patchCommitSha, commitDate, commitMessage, uniDiff, timeLine, timeToPatch, linesChanged);
//
//        // Verify the insertion by checking if the commit URL exists in the database
//        Set<String> existingCommitShas = new HashSet<>();
//        existingCommitShas.add(patchCommitSha);
//
//        // Stub the getExistingPatchCommitShas() method to return the set with the mock databaseHelper
//        when(databaseHelper.getExistingPatchCommitShas()).thenReturn(existingCommitShas);
//
//        // Assert that the commit URL exists in the database after insertion
//        assertTrue(existingCommitShas.contains(patchCommitSha));
//
//        // Verify that the insertPatchCommit method was called with the correct arguments
//        verify(databaseHelper).insertPatchCommit(
//                eq(sourceId),
//                eq(cveId),
//                eq(patchCommitSha),
//                any(Date.class),
//                eq(commitMessage),
//                eq(uniDiff),
//                eq(timeLine),
//                eq(timeToPatch),
//                eq(linesChanged)
//        );
//    }
//
//
//    @Test
//    public void testInsertPatchCommitWithDuplicates() {
//        // Mock the databaseHelper
//        DatabaseHelper databaseHelper = mock(DatabaseHelper.class);
//
//        int sourceId = 1; // Assume a valid source ID
//        String patchCommitSha = "abcdef123456";
//        String cveId = "CVE-2023-3765";
//        java.util.Date commitDate = new java.util.Date();
//        String commitMessage = "Fix vulnerability";
//        String uniDiff = "diff --git a/file1 b/file1\n+++ b/file1\n@@ -1,3 +1,3 @@\n-line1\n-line2\n+line3\n+line4";
//        List<String> timeLine = new ArrayList<>(); // Assume a valid timeline
//        String timeToPatch = "2 days";
//        int linesChanged = 2;
//
//        // Stub the getExistingPatchCommitShas() method to return a set containing the first patch commit SHA
//        Set<String> existingCommitShas = new HashSet<>();
//        existingCommitShas.add(patchCommitSha);
//        when(databaseHelper.getExistingPatchCommitShas()).thenReturn(existingCommitShas);
//
//        // Attempt to insert the first patch commit
//        databaseHelper.insertPatchCommit(sourceId, cveId, patchCommitSha, commitDate, commitMessage, uniDiff, timeLine, timeToPatch, linesChanged);
//
//        // Attempt to insert the same patch commit again
//        try {
//            databaseHelper.insertPatchCommit(sourceId, cveId, patchCommitSha, commitDate, commitMessage, uniDiff, timeLine, timeToPatch, linesChanged);
//        } catch (IllegalArgumentException e) {
//            // The exception is expected to be thrown
//            // Add assertions or verify the exception message, if needed
//            String expectedErrorMessage = "Failed to insert patch commit, as it already exists in the database";
//            assertEquals(expectedErrorMessage, e.getMessage());
//        }
//
//        // Verify that the insertPatchCommit method was called twice with the correct arguments
//        verify(databaseHelper, times(2)).insertPatchCommit(
//                eq(sourceId),
//                eq(cveId),
//                eq(patchCommitSha),
//                any(Date.class),
//                eq(commitMessage),
//                eq(uniDiff),
//                eq(timeLine),
//                eq(timeToPatch),
//                eq(linesChanged)
//        );
//    }

}