package edu.rit.se.nvip.nvd;

import com.zaxxer.hikari.HikariDataSource;
import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.CsvUtils;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.*;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class NvdCveControllerTest {
    @InjectMocks
    private NvdCveController nvdCveController = new NvdCveController();
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
    @Mock
    private CsvUtils mockCsvUtils = mock(CsvUtils.class);

    @Mock
    NvdCveParser mockCveParser = mock(NvdCveParser.class);

    public Set<CompositeVulnerability> genRawVulns(int amount){

        //amount must be a single digit due to the cveId

        Set<CompositeVulnerability> rawVulns = new HashSet<>();

        while (amount != 0){
            RawVulnerability rawVuln = new RawVulnerability(
                    amount,
                    "CVE-2023-" + amount + amount + amount + amount,
                    "desc",
                    new Timestamp(System.currentTimeMillis() + -amount*3600L*1000),
                    new Timestamp(System.currentTimeMillis() + 3600L*1000),
                    new Timestamp(System.currentTimeMillis() + (-amount-10)*3600L*1000),
                    "example" + amount + ".com");
            CompositeVulnerability vuln = new CompositeVulnerability(rawVuln);
            rawVulns.add(vuln);
            amount--;
        }

        return rawVulns;
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
    public void compareReconciledCVEsWithNVDTest() throws SQLException {

        Set<CompositeVulnerability> vulns = genRawVulns(5);

        when(conn.prepareStatement(anyString())).thenReturn(pstmt);
        when(pstmt.executeQuery()).thenReturn(res);
        when(res.next()).thenReturn(true, true, true, true, true, false);
        when(res.getString(anyString())).thenReturn("CVE-2023-1111", "Analyzed",
                "CVE-2023-2222", "Undergoing Analysis",
                "CVE-2023-3333", "Awaiting Analysis",
                "CVE-2023-4444", "Received",
                "CVE-2023-5555", "Not in NVD");


        Set<CompositeVulnerability> result = nvdCveController.compareReconciledCVEsWithNVD(vulns);


        assertEquals(result.size(), 5); //asserts 5 vulns were passed through successfully



    }
}