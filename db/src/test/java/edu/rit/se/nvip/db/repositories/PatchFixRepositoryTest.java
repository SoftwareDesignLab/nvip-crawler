/**
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
*/

package edu.rit.se.nvip.db.repositories;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class PatchFixRepositoryTest {

    @Mock
    DataSource dataSource;
    @Mock
    Connection mockConnection;
    @Mock
    PreparedStatement mockPS;
    @Mock
    ResultSet mockRS;

    PatchFixRepository repository;


    private static final String TEST_CVE_ID = "CVE-2023-1001";

    @SneakyThrows
    @BeforeEach
    void initializeMocks(){
        when(mockPS.executeQuery()).thenReturn(mockRS);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPS);
        when(dataSource.getConnection()).thenReturn(mockConnection);

        repository = new PatchFixRepository(dataSource);
    }


    @Test
    @SneakyThrows
    public void testInsertPatchSourceURL() {
        String sourceURL = "https://example.com";
        int sourceId = repository.insertPatchSourceURL(new HashMap<>(), TEST_CVE_ID, sourceURL);
        assertFalse(sourceId >= 0);
    }

    @Test
    @SneakyThrows
    public void testInsertPatchCommit() {
        // todo this uses the wrong approach to mocking. the repo shouldn't be mocked directly
        // Mock the databaseHelper
        PatchFixRepository databaseHelper = mock(PatchFixRepository.class);
        int sourceId = 1; // Assume a valid source ID
        String patchCommitSha = "abcdef123456";
        String cveId = "CVE-2023-3765";
        java.util.Date commitDate = new java.util.Date();
        String commitMessage = "Fix vulnerability";
        String uniDiff = "diff --git a/file1 b/file1\n+++ b/file1\n@@ -1,3 +1,3 @@\n-line1\n-line2\n+line3\n+line4";
        List<String> timeLine = new ArrayList<>(); // Assume a valid timeline
        String timeToPatch = "2 days";
        int linesChanged = 2;

        // Insert the patch commit (Assuming your databaseHelper has the appropriate method signature)
        databaseHelper.insertPatchCommit(sourceId, cveId, patchCommitSha, commitDate, commitMessage, uniDiff, timeLine, timeToPatch, linesChanged);

        // Verify the insertion by checking if the commit URL exists in the database
        Set<String> existingCommitShas = new HashSet<>();
        existingCommitShas.add(patchCommitSha);

        // Stub the getExistingPatchCommitShas() method to return the set with the mock databaseHelper
        when(databaseHelper.getExistingPatchCommitShas()).thenReturn(existingCommitShas);

        // Assert that the commit URL exists in the database after insertion
        assertTrue(existingCommitShas.contains(patchCommitSha));

        // Verify that the insertPatchCommit method was called with the correct arguments
        verify(databaseHelper).insertPatchCommit(
                eq(sourceId),
                eq(cveId),
                eq(patchCommitSha),
                any(Date.class),
                eq(commitMessage),
                eq(uniDiff),
                eq(timeLine),
                eq(timeToPatch),
                eq(linesChanged)
        );
    }


    @Test
    @SneakyThrows
    public void testInsertPatchCommitWithDuplicates() {
        // todo this uses the wrong approach to mocking. the repo shouldn't be mocked directly
        // Mock the databaseHelper
        PatchFixRepository databaseHelper = mock(PatchFixRepository.class);

        int sourceId = 1; // Assume a valid source ID
        String patchCommitSha = "abcdef123456";
        String cveId = "CVE-2023-3765";
        java.util.Date commitDate = new java.util.Date();
        String commitMessage = "Fix vulnerability";
        String uniDiff = "diff --git a/file1 b/file1\n+++ b/file1\n@@ -1,3 +1,3 @@\n-line1\n-line2\n+line3\n+line4";
        List<String> timeLine = new ArrayList<>(); // Assume a valid timeline
        String timeToPatch = "2 days";
        int linesChanged = 2;

        // Stub the getExistingPatchCommitShas() method to return a set containing the first patch commit SHA
        Set<String> existingCommitShas = new HashSet<>();
        existingCommitShas.add(patchCommitSha);
        when(databaseHelper.getExistingPatchCommitShas()).thenReturn(existingCommitShas);

        // Attempt to insert the first patch commit
        databaseHelper.insertPatchCommit(sourceId, cveId, patchCommitSha, commitDate, commitMessage, uniDiff, timeLine, timeToPatch, linesChanged);

        // Attempt to insert the same patch commit again
        try {
            databaseHelper.insertPatchCommit(sourceId, cveId, patchCommitSha, commitDate, commitMessage, uniDiff, timeLine, timeToPatch, linesChanged);
        } catch (IllegalArgumentException e) {
            // The exception is expected to be thrown
            // Add assertions or verify the exception message, if needed
            String expectedErrorMessage = "Failed to insert patch commit, as it already exists in the database";
            assertEquals(expectedErrorMessage, e.getMessage());
        }

        // Verify that the insertPatchCommit method was called twice with the correct arguments
        verify(databaseHelper, times(2)).insertPatchCommit(
                eq(sourceId),
                eq(cveId),
                eq(patchCommitSha),
                any(Date.class),
                eq(commitMessage),
                eq(uniDiff),
                eq(timeLine),
                eq(timeToPatch),
                eq(linesChanged)
        );
    }

}