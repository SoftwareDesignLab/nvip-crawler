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
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class CveJobTrackRepositoryTest {

    @Mock DataSource dataSource;
    @Mock Connection mockConnection;
    @Mock PreparedStatement mockPS;
    @Mock
    ResultSet mockRS;

    CveJobTrackRepository repository;

    @SneakyThrows
    @BeforeEach
    void initializeMocks(){
        when(mockPS.executeQuery()).thenReturn(mockRS);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPS);
        when(dataSource.getConnection()).thenReturn(mockConnection);

        repository = new CveJobTrackRepository(dataSource);
    }

    @SneakyThrows
    @Test
    public void testAddJobForCve() {
        repository.addJobForCVE("CVE-1234-5678");

        verify(mockPS, atMostOnce()).executeUpdate();
    }

    @SneakyThrows
    @Test
    public void testCveFoundInJobTrack() {
        ResultSet mockRS = mock(ResultSet.class);
        when(mockRS.next()).thenReturn(true);
        when(mockRS.getInt("numInJobtrack")).thenReturn(1);
        when(mockPS.executeQuery()).thenReturn(mockRS);

        assertTrue(repository.isCveInJobTrack("CVE-1234-5678"));
    }

    @SneakyThrows
    @Test
    public void testCveNotFoundInJobTrack() {
        ResultSet mockRS = mock(ResultSet.class);
        when(mockRS.next()).thenReturn(true);
        when(mockRS.getInt("numInJobtrack")).thenReturn(0);
        when(mockPS.executeQuery()).thenReturn(mockRS);

        repository.isCveInJobTrack("CVE-1234-5678");

        assertFalse(repository.isCveInJobTrack("CVE-1234-5678"));
    }
    @Test
    @SneakyThrows
    public void getJobsTest() {
        when(mockRS.next()).thenReturn(true, true, false);
        when(mockRS.getString("cve_id")).thenReturn("CVE-2021-1234", "CVE-2021-5678");


        // Call the method under test
        Set<String> result = repository.getJobs();

        // Verify the expected output
        Set<String> expected = new HashSet<>();
        expected.add("CVE-2021-1234");
        expected.add("CVE-2021-5678");
        assertEquals(expected, result);
    }
}
