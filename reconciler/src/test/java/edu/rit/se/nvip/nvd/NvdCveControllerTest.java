package edu.rit.se.nvip.nvd;

import com.zaxxer.hikari.HikariDataSource;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.NvdVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
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

import java.sql.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class NvdCveControllerTest {
    private NvdCveController nvdCveController;

    @Mock
    private Logger logger = LogManager.getLogger(getClass().getSimpleName());
    @Mock
    private DatabaseHelper dbh;


    @Mock
    private HikariDataSource hds;
    @Mock
    private Connection conn;
    @Mock
    private PreparedStatement pstmt;
    @Mock
    private ResultSet res;

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

            this.nvdCveController = new NvdCveController();
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
    public void testCompareReconciledCVEsWithNVD() throws SQLException {
        RawVulnerability vulnRaw = new RawVulnerability(
                1,
                "CVE-2023-1111",
               "desc",
                new Timestamp(System.currentTimeMillis() + -1*3600L*1000),
                new Timestamp(System.currentTimeMillis() + 3600L*1000),
                new Timestamp(System.currentTimeMillis() + -10*3600L*1000),
                "example.com");

        RawVulnerability vulnRaw2 = new RawVulnerability(
                1,
                "CVE-2023-2222",
                "desc",
                new Timestamp(System.currentTimeMillis() + -2*3600L*1000),
                new Timestamp(System.currentTimeMillis() + 3600L*1000),
                new Timestamp(System.currentTimeMillis() + -12*3600L*1000),
                "example2.com");
        RawVulnerability vulnRaw3 = new RawVulnerability(
                1,
                "CVE-2023-3333",
                "desc",
                new Timestamp(System.currentTimeMillis() + -2*3600L*1000),
                new Timestamp(System.currentTimeMillis() + 3600L*1000),
                new Timestamp(System.currentTimeMillis() + -12*3600L*1000),
                "example3.com");
        RawVulnerability vulnRaw4 = new RawVulnerability(
                1,
                "CVE-2023-4444",
                "desc",
                new Timestamp(System.currentTimeMillis() + -2*3600L*1000),
                new Timestamp(System.currentTimeMillis() + 3600L*1000),
                new Timestamp(System.currentTimeMillis() + -12*3600L*1000),
                "example4.com");

        RawVulnerability vulnRaw5 = new RawVulnerability(
                1,
                "CVE-2023-5555",
                "desc",
                new Timestamp(System.currentTimeMillis() + -2*3600L*1000),
                new Timestamp(System.currentTimeMillis() + 3600L*1000),
                new Timestamp(System.currentTimeMillis() + -12*3600L*1000),
                "example5.com");


        // Create some test data
        CompositeVulnerability vuln1 = new CompositeVulnerability(vulnRaw);
        CompositeVulnerability vuln2 = new CompositeVulnerability(vulnRaw2);
        CompositeVulnerability vuln3 = new CompositeVulnerability(vulnRaw3);
        CompositeVulnerability vuln4 = new CompositeVulnerability(vulnRaw4);
        CompositeVulnerability vuln5 = new CompositeVulnerability(vulnRaw5);
        Set<CompositeVulnerability> vulns = new HashSet<>();
        vulns.add(vuln1);
        vulns.add(vuln2);
        vulns.add(vuln3);
        vulns.add(vuln4);
        vulns.add(vuln5);

        when(conn.prepareStatement(anyString())).thenReturn(pstmt);
        when(pstmt.executeQuery()).thenReturn(res);
        when(res.next()).thenReturn(true, true, true, true, true, false);
        when(res.getString(anyString())).thenReturn("CVE-2023-1111", "ANALYZED",
                "CVE-2023-2222", "UNDERGOINGANALYSIS",
                "CVE-2023-3333", "AWAITINGANALYSIS",
                "CVE-2023-4444", "RECEIVED",
                "CVE-2023-5555", "NOTINNVD");
        when(res.getTimestamp(anyInt())).thenReturn(new Timestamp(System.currentTimeMillis()));


        Set<CompositeVulnerability> result = nvdCveController.compareReconciledCVEsWithNVD(vulns);


        assertEquals(result.size(), 5); //asserts 5 vulns were passed through successfully



    }

    @Test
    public void fetchNVDCVEsTest() {
        String nvdApiPath = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubstartDate=<StartDate>&pubEndDate=<EndDate>";
        int requestLimit = 10;

        HashMap<String, NvdVulnerability> result = nvdCveController.fetchNVDCVEs(nvdApiPath, requestLimit);

        // Perform assertions on the result
        // Assertions.assertEquals(expectedResult, result);
    }

    @Test
    public void pullNvdCveTest() {
        String filepath = "path/to/output.csv";

        int result = nvdCveController.pullNvdCve(filepath);

        // Perform assertions on the result
        // Assertions.assertEquals(expectedResult, result);
    }
}