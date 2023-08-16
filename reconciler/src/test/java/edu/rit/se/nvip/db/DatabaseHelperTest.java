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
import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.characterizer.enums.CVSSSeverityClass;
import edu.rit.se.nvip.characterizer.enums.VDOLabel;
import edu.rit.se.nvip.characterizer.enums.VDONounGroup;
import edu.rit.se.nvip.cwe.CWE;
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
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Field;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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

    private void setMocking() {
        try {
            when(hds.getConnection()).thenReturn(conn);
            when(conn.prepareStatement(any())).thenReturn(pstmt);
            when(pstmt.executeQuery()).thenReturn(res);
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
            when(res.next()).thenReturn(true, true, false);
            when(res.getString("cve_id")).thenReturn("CVE-2021-1234", "CVE-2021-5678");


            // Call the method under test
            Set<String> result = dbh.getJobs();

            // Verify the expected output
            Set<String> expected = new HashSet<>();
            expected.add("CVE-2021-1234");
            expected.add("CVE-2021-5678");
            assertEquals(expected, result);
        } catch (SQLException e) {
            logger.error("Error loading database");
        }
    }
    @Test
    public void getRawVulnerabilitiesTest() {
        try {
            when(res.next()).thenReturn(true, false);

            // Set up the expected data
            String cveId = "CVE-2023-5678";

            // Call the method under test
            Set<RawVulnerability> result = dbh.getRawVulnerabilities(cveId);

            // Verify the expected output
            assertEquals(1, result.size());

            // Verify pstmt.setString() call
            verify(pstmt).setString(1, cveId);
        } catch (SQLException ignored) {
            logger.error("Error loading database");
        }
    }

    @Test
    public void markGarbageTest() throws SQLException {

        Set<RawVulnerability> mockedRawVulns = new HashSet<>();
        mockedRawVulns.add(new RawVulnerability(1, "CVE-2021-1234", "Description", null, null, null, ""));
        mockedRawVulns.add(new RawVulnerability(2, "CVE-2021-5678", "Description", null, null, null, ""));

        // Call the updateFilterStatus method
        dbh.updateFilterStatus(mockedRawVulns);

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
            when(res.next()).thenReturn(true, true, false);
            when(res.getInt(anyString())).thenReturn(1);
            when(res.getString(anyString())).thenReturn("desc");
            when(res.getTimestamp(anyString())).thenReturn(new Timestamp(System.currentTimeMillis()));

            Set<RawVulnerability> rawVulns = dbh.getUsedRawVulnerabilities("cveId");

           verify(pstmt).setString(1, "cveId");

            assertEquals(1, rawVulns.size());

       } catch (SQLException e) {
           logger.error("Error loading Database");
        }
    }
    @Test
    public void insertOrUpdateVulnerabilityFullTest() {
        try{
            when(conn.prepareStatement(anyString(), eq(Statement.RETURN_GENERATED_KEYS))).thenReturn(pstmt);
            when(pstmt.getGeneratedKeys()).thenReturn(res);
            when(res.next()).thenReturn(true);
            when(res.getInt(1)).thenReturn(1);

            RawVulnerability rawVuln = new RawVulnerability(1, "CVE-2023-1111", "desc", offset(-1), offset(1), offset(-10), "example.com");

            Set<RawVulnerability> rawVulns = new HashSet<>();
            rawVulns.add(rawVuln);

            CompositeVulnerability vuln = new CompositeVulnerability(rawVuln);
            vuln.setPotentialSources(rawVulns);

            // Call the method to be tested
            int result = dbh.insertOrUpdateVulnerabilityFull(vuln);


            // Assert the result
            assertEquals(1, result);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void insertCWEsTest() throws SQLException {
        // Create a sample CompositeVulnerability object
        CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, "cve-1",
                "The ntpd_driver component before 1.3.0 and 2.x before 2.2.0 for Robot Operating System (ROS) allows attackers, " +
                        "who control the source code of a different node in the same ROS application, to change a robot's behavior. " +
                        "This occurs because a topic name depends on the attacker-controlled time_ref_topic parameter.",
                new Timestamp(System.currentTimeMillis()),
                new Timestamp(System.currentTimeMillis()),
                new Timestamp(System.currentTimeMillis()),
                "www.example.com"));

        CWE cwe1 = new CWE(123, "cwe1", "cwe");
        CWE cwe2 = new CWE(234, "cwe2", "cwe");
        CWE cwe3 = new CWE(345, "cwe3", "cwe");

        vuln.addCWE(cwe1);
        vuln.addCWE(cwe2);
        vuln.addCWE(cwe3);


        // Call the insertCWEs method
        int result = dbh.insertCWEs(vuln);

        // Verify the expected method calls and parameter values
        verify(conn).setAutoCommit(false);
        verify(pstmt, times(3)).addBatch();
        verify(pstmt, times(4)).setString(1, "cve-1");
        verify(pstmt).execute();

        verify(pstmt).setInt(2, 123);
        verify(pstmt).setInt(2, 234);
        verify(pstmt).setInt(2, 345);

        verify(pstmt, times(3)).addBatch();
        verify(pstmt).executeBatch();
        verify(conn).commit();

        // Verify that pstmt.execute() is called
        verify(pstmt).execute();

        // Verify the result of the insertCWEs method
        assertEquals(1, result);
    }

    @Test
    public void insertCvssBatchTest() throws SQLException {
        Set<CompositeVulnerability> vulns = new HashSet<>();

        CompositeVulnerability vuln1 = new CompositeVulnerability(new RawVulnerability(1, "CVE-1", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));
        CompositeVulnerability vuln2 = new CompositeVulnerability(new RawVulnerability(1, "CVE-2", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));
        vuln1.addCvssScore(new CvssScore(vuln1.getCveId(), CVSSSeverityClass.LOW, 1.0, 1.0, 1.0));
        vuln2.addCvssScore(new CvssScore(vuln2.getCveId(), CVSSSeverityClass.HIGH, 1.0, 1.0, 1.0));
        vulns.add(vuln1);
        vulns.add(vuln2);


        int res = dbh.insertCvssBatch(vulns);

        verify(pstmt).setString(1, vuln1.getCvssScoreInfo().getCveId());
        verify(pstmt).setString(1, vuln2.getCvssScoreInfo().getCveId());
        verify(pstmt, times(2)).setDouble(2, 1.0);
        verify(pstmt).setDouble(3, 5.0);
        verify(pstmt).setDouble(3, 1.0);
        verify(pstmt, times(2)).addBatch();
        verify(pstmt).executeBatch();

        assertEquals(1, res);
    }

    @Test
    public void insertVdoBatchTest() throws SQLException {
        Set<CompositeVulnerability> vulns = new HashSet<>();

        CompositeVulnerability vuln1 = new CompositeVulnerability(new RawVulnerability(1, "CVE-1", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));
        CompositeVulnerability vuln2 = new CompositeVulnerability(new RawVulnerability(1, "CVE-2", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));

        vuln1.addVdoCharacteristic(new VdoCharacteristic(vuln1.getCveId(), VDOLabel.LOCAL, 1.0, VDONounGroup.CONTEXT));
        vuln2.addVdoCharacteristic(new VdoCharacteristic(vuln2.getCveId(), VDOLabel.LOCAL, 1.0, VDONounGroup.CONTEXT));

        vulns.add(vuln1);
        vulns.add(vuln2);


        int res = dbh.insertVdoBatch(vulns);

        verify(conn).setAutoCommit(false);
        verify(pstmt).executeUpdate();
        verify(pstmt, times(2)).addBatch();
        verify(pstmt).setString(1, vuln1.getVdoCharacteristics().get(0).getCveId());
        verify(pstmt).setString(1, vuln2.getVdoCharacteristics().get(0).getCveId());
        verify(pstmt, times(2)).setString(2, vuln1.getVdoCharacteristics().get(0).getVdoLabel().vdoLabelName);
        verify(pstmt, times(2)).setString(3, vuln1.getVdoCharacteristics().get(0).getVdoNounGroup().vdoNounGroupName);
        verify(pstmt, times(2)).setDouble(4, 1.0);
        verify(pstmt).executeBatch();
        verify(conn).commit();

        assertEquals(1, res);
    }
    @Test
    public void getMitreDataCountTest(){
        try {
            when(res.next()).thenReturn(true, false);
            when(res.getInt(anyString())).thenReturn(0, 1);

            boolean result = dbh.isMitreTableEmpty();

            assertTrue(result);
            result = dbh.isMitreTableEmpty();
            assertFalse(result);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void insertRunTest() throws SQLException {
        Set<CompositeVulnerability> vulns = new HashSet<>();

        CompositeVulnerability vuln1 = new CompositeVulnerability(new RawVulnerability(1, "CVE-1", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));
        vulns.add(vuln1);

        RunStats run = new RunStats(vulns);

        int res = dbh.insertRun(run);

        verify(pstmt).setInt(2, 1);
        verify(pstmt).setInt(3, 1);
        verify(pstmt).setInt(4, 0);
        verify(pstmt).setInt(5, 1);
        verify(pstmt).setInt(6, 1);
        verify(pstmt).setInt(7, 1);
        verify(pstmt).setDouble(8, 0);
        verify(pstmt).setDouble(9, 0);

        verify(pstmt).execute();
        assertEquals(1, res);
    }
    @Test
    public void backfillNvdTimegapsTest() throws SQLException {
        Set<NvdVulnerability> nvdVulns = new HashSet<>();
        NvdVulnerability vuln = new NvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed");
        NvdVulnerability vuln2 = new NvdVulnerability("cve-2", new Timestamp(System.currentTimeMillis()), "Received");
        nvdVulns.add(vuln);
        nvdVulns.add(vuln2);

        int res = dbh.backfillNvdTimegaps(nvdVulns);

        verify(pstmt).setString(1, "cve-1");
        verify(pstmt).setString(1, "cve-2");
        verify(pstmt, times(2)).addBatch();
        verify(pstmt).executeBatch();

        assertEquals(1, res);
    }

    @Test
    public void backfillMitreTimegapsTest() throws SQLException {
        Set<MitreVulnerability> mitreVulns = new HashSet<>();
        MitreVulnerability vuln = new MitreVulnerability("cve-1", "Public");
        MitreVulnerability vuln2 = new MitreVulnerability("cve-2",  "Reserved");
        mitreVulns.add(vuln);
        mitreVulns.add(vuln2);

        int res = dbh.backfillMitreTimegaps(mitreVulns);

        verify(pstmt).setString(1, "cve-1");
        verify(pstmt).setString(1, "cve-2");
        verify(pstmt, times(2)).addBatch();
        verify(pstmt).executeBatch();

        assertEquals(1, res);

    }

    @Test
    public void insertTimeGapsForNewVulnsTest() throws SQLException {
        Set<CompositeVulnerability> compVulns = new HashSet<>();
        CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, "CVE-2023-1111", "desc", offset(-1), offset(1), offset(-10), "example.com"));
        CompositeVulnerability vuln2 = new CompositeVulnerability(new RawVulnerability(1, "CVE-2023-2222", "desc", offset(-1), offset(1), offset(-10), "example.com"));

        MitreVulnerability mVuln = new MitreVulnerability("cve-1", "Public");
        NvdVulnerability nVuln = new NvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed");

        vuln.setMitreVuln(mVuln);
        vuln2.setNvdVuln(nVuln);

        compVulns.add(vuln);
        compVulns.add(vuln2);

        int res = dbh.insertTimeGapsForNewVulns(compVulns);

        verify(pstmt).setString(1, "CVE-2023-1111");
        verify(pstmt).setString(1, "CVE-2023-2222");
        verify(pstmt).setString(2, "nvd");
        verify(pstmt).setString(2, "mitre");
        verify(pstmt, times(2)).addBatch();
        verify(pstmt).executeBatch();

        assertEquals(1, res);
    }

    @Test
    public void attachNvdVulnsTest() throws SQLException {
        Set<CompositeVulnerability> vulns = new HashSet<>();

        when(res.next()).thenReturn(true, false);
        when(res.getString(anyString())).thenReturn("CVE-2023-2222", "Analyzed");

        CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, "CVE-2023-2222", "desc", offset(-1), offset(1), offset(-10), "example.com"));
        NvdVulnerability nVuln = new NvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed");
        vuln.setNvdVuln(nVuln);
        Set<CompositeVulnerability> set = dbh.attachNvdVulns(vulns);

        assertTrue(set.isEmpty());

        vulns.add(vuln);

        set = dbh.attachNvdVulns(vulns);

        verify(pstmt).setString(1, "CVE-2023-2222");

        assertEquals(1, set.size());
        List<CompositeVulnerability> list = new ArrayList<>(set);

        assertEquals(NvdVulnerability.NvdStatus.ANALYZED, list.get(0).getNvdVuln().getStatus());

    }

    @Test
    public void attachMitreVulnsTest() throws SQLException {
        Set<CompositeVulnerability> vulns = new HashSet<>();

        when(res.next()).thenReturn(true, false);
        when(res.getString(anyString())).thenReturn("CVE-2023-2222", "Public");

        CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, "CVE-2023-2222", "desc", offset(-1), offset(1), offset(-10), "example.com"));
        MitreVulnerability mVuln = new MitreVulnerability("cve-1", "Public");
        vuln.setMitreVuln(mVuln);
        Set<CompositeVulnerability> set = dbh.attachMitreVulns(vulns);

        assertTrue(set.isEmpty());

        vulns.add(vuln);

        set = dbh.attachMitreVulns(vulns);

        verify(pstmt).setString(1, "CVE-2023-2222");

        assertEquals(1, set.size());
        List<CompositeVulnerability> list = new ArrayList<>(set);

        assertEquals(MitreVulnerability.MitreStatus.PUBLIC, list.get(0).getMitreVuln().getStatus());
    }

    @Test
    public void upsertNvdDataTest() throws SQLException {
        Set<NvdVulnerability> vulns = new HashSet<>();
        NvdVulnerability vuln = new NvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed");
        NvdVulnerability vuln2 = new NvdVulnerability("cve-2", new Timestamp(System.currentTimeMillis()), "Not in NVD");
        vulns.add(vuln);
        vulns.add(vuln2);

        when(res.next()).thenReturn(true, false);
        when(res.getString(1)).thenReturn("cve-1");


        Set<NvdVulnerability> set = dbh.upsertNvdData(vulns);

        verify(pstmt).setString(1, "cve-1");
        verify(pstmt).setString(1, "cve-2");
        verify(pstmt).setString(3, "Analyzed");
        verify(pstmt).setString(3, "Not in NVD");
        verify(pstmt, times(2)).addBatch();
        verify(pstmt).executeBatch();

        assertEquals(1, set.size());
    }

    @Test
    public void upsertMitreDataTest() throws SQLException {
        Set<MitreVulnerability> mitreVulns = new HashSet<>();
        MitreVulnerability vuln = new MitreVulnerability("cve-1", "Public");
        MitreVulnerability vuln2 = new MitreVulnerability("cve-2",  "Reserved");
        mitreVulns.add(vuln);
        mitreVulns.add(vuln2);

        when(res.next()).thenReturn(true, false);
        when(res.getString(1)).thenReturn("cve-1");

        Set<MitreVulnerability> set = dbh.upsertMitreData(mitreVulns);

        verify(pstmt).setString(1, "cve-1");
        verify(pstmt).setString(1, "cve-2");
        verify(pstmt).setString(2, "Public");
        verify(pstmt).setString(2, "Reserved");
        verify(pstmt, times(2)).addBatch();
        verify(pstmt).executeBatch();

        assertEquals(1, set.size());

    }
}
