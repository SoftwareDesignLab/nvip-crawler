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
package edu.rit.se.nvip.db;

import com.zaxxer.hikari.HikariDataSource;
import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.model.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Field;
import java.sql.*;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Collection of tests for the DatabaseHelper class. The general approach here it to use mocking/spying in order to
 * sever dependenies on database connections. Generally, SQL arguments are verified, execute commands are verified, and
 * return values are verified where applicable.
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class DatabaseHelperTest {
    private Logger logger = LogManager.getLogger(getClass().getSimpleName());

    private DatabaseHelper dbh;

    @Mock
    private HikariDataSource hds;
    @Mock
    private Connection conn;
    @Mock
    private PreparedStatement pstmt;
    @Mock
    private ResultSet res;

    private final String dummyCveId = "CVE-xxxx-xxx";
    private final long dummyMillis = System.currentTimeMillis();

    private Timestamp offset(int nHours) {
        return new Timestamp(dummyMillis + nHours*3600L*1000);
    }
    private RawVulnerability genRawVuln(int id) {
        return new RawVulnerability(id, dummyCveId, "description"+id, offset(-id), offset(id), offset(-10), "website"+id );
    }

    private void setMocking() {
        try {
            when(hds.getConnection()).thenReturn(conn);
            when(conn.prepareStatement(any())).thenReturn(pstmt);
            when(pstmt.executeQuery()).thenReturn(res);
        } catch (SQLException ignored) {}
    }

    /**
     * Sets up the "database" results to return n rows
     * @param n Number of rows (number of times next() will return true)
     */
    private void setResNextCount(int n) {
        try {
            when(res.next()).thenAnswer(new Answer<Boolean>() {
                private int iterations = n;
                public Boolean answer(InvocationOnMock invocation) {
                    return iterations-- > 0;
                }
            });
        } catch (SQLException ignored) {}
    }

    /**
     * Helper method for populating the "database" results.
     * @param getStringArg Name of the column to retrieve from. Used for that column's value as well with a suffix.
     * @param count Number of results to populate.
     */
    private void setResStrings(String getStringArg, int count) {
        try {
            when(res.getString(getStringArg)).thenAnswer(new Answer<String>() {
                private int index = 0;

                public String answer(InvocationOnMock invocation) {
                    if (index == count) {
                        return null;
                    }
                    return getStringArg + index++;
                }
            });
        } catch (SQLException ignored) {}
    }

    /**
     * Helper method for populating the "database" results. Just returns multiples of 1337
     * @param getIntArg Name of the column to retrieve from.
     * @param count Number of results to populate.
     */
    private void setResInts(String getIntArg, int count) {
        try {
            when(res.getInt(getIntArg)).thenAnswer(new Answer<Integer>() {
                private int index = 0;

                public Integer answer(InvocationOnMock invocation) {
                    if (index == count) {
                        return 0;
                    }
                    return 1337 * index++;
                }
            });
        } catch (SQLException ignored) {}
    }

    @BeforeClass
    public static void classSetUp() {
        try (MockedConstruction<HikariDataSource> mock = mockConstruction(HikariDataSource.class)){
            // forces a constructor, only want to do once
            DatabaseHelper.getInstance();
        }
    }

    @Before
    public void setUp() {

        try (MockedConstruction<HikariDataSource> mock = mockConstruction(HikariDataSource.class)){

            this.dbh = DatabaseHelper.getInstance();
            ReflectionTestUtils.setField(this.dbh, "dataSource", this.hds);
            this.setMocking();

        }

    }

    @AfterClass
    public static void tearDown() {

        try (MockedConstruction<HikariDataSource> mock = mockConstruction(HikariDataSource.class)){
            DatabaseHelper dbh = DatabaseHelper.getInstance();
            ReflectionTestUtils.setField(dbh, "databaseHelper", null);

        }
    }

    @Test
    public void getInstanceTest() {
        assertNotNull(DatabaseHelper.getInstance());
    }

    @Test
    public void getConnectionTest() {
        try {
            Connection conn = dbh.getConnection();
            assertNotNull(conn);
        } catch (SQLException ignored) {
        }
    }

    @Test
    public void testDbConnectionTest() {
        try {
            assertTrue(this.dbh.testDbConnection());
            when(hds.getConnection()).thenReturn(null);
            assertFalse(this.dbh.testDbConnection());
        } catch (SQLException ignored) {}
    }

    @Test
    public void getJobsTest() {
        try {
            // Set up the mock objects and their behavior
            when(conn.prepareStatement(anyString())).thenReturn(pstmt);
            when(pstmt.executeQuery()).thenReturn(res);
            when(res.next()).thenReturn(true, true, false);
            when(res.getString("cve_id")).thenReturn("CVE-2021-1234", "CVE-2021-5678");

            // Access the private GET_JOBS constant using reflection
            Field getJobsField = DatabaseHelper.class.getDeclaredField("GET_JOBS");
            getJobsField.setAccessible(true);


            // Call the method under test
            Set<String> result = dbh.getJobs();

            // Verify the expected output
            Set<String> expected = new HashSet<>();
            expected.add("CVE-2021-1234");
            expected.add("CVE-2021-5678");
            assertEquals(expected, result);
        } catch (SQLException | NoSuchFieldException e) {
            logger.error("Error loading database");
        }
    }
    @Test
    public void getRawVulnerabilitiesTest() {
        try {
            // Set up the mock objects and their behavior
            when(conn.prepareStatement(anyString())).thenReturn(pstmt);
            when(pstmt.executeQuery()).thenReturn(res);
            when(res.next()).thenReturn(true, true, false);

            // Set up the expected data
            String cveId = "CVE-2023-5678";

            // Call the method under test
            Set<RawVulnerability> result = dbh.getRawVulnerabilities(cveId);

            // Verify the expected output
            assertEquals(2, result.size());

            // Verify pstmt.setString() call
            verify(pstmt).setString(1, cveId);
        } catch (SQLException ignored) {
            logger.error("Error loading database");
        }
    }

    @Test
    public void markGarbageTest() throws SQLException {
        // Create a mocked Connection, PreparedStatement, and set of RawVulnerabilities
        Set<RawVulnerability> mockedRawVulns = new HashSet<>();
        mockedRawVulns.add(new RawVulnerability(1, "CVE-2021-1234", "Description", null, null, null, ""));
        mockedRawVulns.add(new RawVulnerability(2, "CVE-2021-5678", "Description", null, null, null, ""));

        // Mock the behavior of the getConnection and prepareStatement methods
        when(dbh.getConnection()).thenReturn(conn);
        when(conn.prepareStatement(anyString())).thenReturn(pstmt);

        // Call the markGarbage method
        dbh.markGarbage(mockedRawVulns);

        // Verify that pstmt.setInt() is called with the correct arguments
        verify(pstmt, times(2)).setInt(eq(1), eq(1));
        verify(pstmt).setInt(eq(2), eq(1));
        verify(pstmt).setInt(eq(2), eq(2));

        // Verify that pstmt.addBatch() is called for each RawVulnerability
        verify(pstmt, times(2)).addBatch();

        // Verify that pstmt.executeBatch() is called once
        verify(pstmt).executeBatch();
    }

    @Test
    public void testGetCompositeVulnerability() throws SQLException {
        // Set up the behavior of the mocks
        when(conn.prepareStatement(anyString())).thenReturn(pstmt);
        when(pstmt.executeQuery()).thenReturn(res);
        when(res.next()).thenReturn(true, false, true);
        when(res.getInt(anyString())).thenReturn(1);
        when(res.getString(anyString())).thenReturn("1");
        when(res.getTimestamp(anyString())).thenReturn(new Timestamp(System.currentTimeMillis()));

        CompositeVulnerability vuln = dbh.getCompositeVulnerability("1");

        assertNotNull(vuln);

    }

    @Test
    public void getUsedRawVulnerabilitiesTest() {
       try{
           // Set up the behavior of the mocks
            when(conn.prepareStatement(anyString())).thenReturn(pstmt);
            when(pstmt.executeQuery()).thenReturn(res);
            when(res.next()).thenReturn(true, true, false);
            when(res.getInt(anyString())).thenReturn(1);
            when(res.getString(anyString())).thenReturn("desc");
            when(res.getTimestamp(anyString())).thenReturn(new Timestamp(System.currentTimeMillis()));

            Set<RawVulnerability> rawVulns = dbh.getUsedRawVulnerabilities("cveId");

           verify(pstmt).setString(1, "cveId");

            assertEquals(2, rawVulns.size());

       } catch (SQLException e) {
           logger.error("Error loading Database");
        }
    }
    @Test
    public void insertOrUpdateVulnerabilityFullTest() {
        try{
            when(conn.prepareStatement(anyString())).thenReturn(pstmt);
            when(conn.prepareStatement(anyString(), eq(Statement.RETURN_GENERATED_KEYS))).thenReturn(pstmt);
            when(pstmt.getGeneratedKeys()).thenReturn(res);
            when(res.next()).thenReturn(true);
            when(res.getInt(1)).thenReturn(1);

            RawVulnerability rawVuln = genRawVuln(1);
            CompositeVulnerability vuln = new CompositeVulnerability(rawVuln);

            // Call the method to be tested
            int result = dbh.insertOrUpdateVulnerabilityFull(vuln);


            // Assert the result
            assertEquals(1, result);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }


    @Test
    public void getAllNvdCVEsTest() {
        try {
            // Set up the behavior of the mocks
            when(conn.prepareStatement(anyString())).thenReturn(pstmt);
            when(pstmt.executeQuery()).thenReturn(res);
            when(res.next()).thenReturn(true, true, false);
            when(res.getString("cve_id")).thenReturn("CVE-2021-1234", "CVE-2021-5678");
            when(res.getTimestamp("published_date")).thenReturn(new Timestamp(System.currentTimeMillis()));
            when(res.getString("status")).thenReturn("ANALYZED");

            // Access the private GET_ALL_NEW_CVES constant using reflection
            Field getNewCvesField = DatabaseHelper.class.getDeclaredField("GET_ALL_NEW_CVES");
            getNewCvesField.setAccessible(true);
            String getNewCvesValue = (String) getNewCvesField.get(dbh);

            // Call the method under test
            ArrayList<NvdVulnerability> result = dbh.getAllNvdCVEs();

            // Verify the expected output
            assertEquals(2, result.size());
            assertEquals("CVE-2021-1234", result.get(0).getCveId());
            assertEquals("CVE-2021-5678", result.get(1).getCveId());

            // Verify that pstmt.prepareStatement() is called with the correct argument
            verify(conn).prepareStatement(getNewCvesValue);
        } catch (SQLException | NoSuchFieldException | IllegalAccessException e) {
            logger.error("Error loading Database");
        }
    }

    @Test
    public void insertNvdCveTest() throws SQLException {
        // Create a sample NvdVulnerability object
        NvdVulnerability nvdCve = new NvdVulnerability("CVE-2023-1234", new Timestamp(System.currentTimeMillis()), NvdVulnerability.nvdStatus.ANALYZED);

        // Call the insertNvdCve method
        int result = dbh.insertNvdCve(nvdCve);

        // Verify that pstmt.setString() and pstmt.setTimestamp() are called with the correct arguments
        verify(pstmt).setString(1, "CVE-2023-1234");
        verify(pstmt).setTimestamp(2, nvdCve.getPublishDate());
        verify(pstmt).setString(3, "ANALYZED");

        // Verify that pstmt.execute() is called
        verify(pstmt).execute();

        // Verify the result of the insertNvdCve method
        assertEquals(1, result);
    }
}
