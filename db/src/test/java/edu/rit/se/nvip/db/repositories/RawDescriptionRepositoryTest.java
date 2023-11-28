package edu.rit.se.nvip.db.repositories;

import edu.rit.se.nvip.db.model.RawVulnerability;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import javax.sql.DataSource;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;



@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class RawDescriptionRepositoryTest {

    @Mock DataSource dataSource;
    @Mock Connection mockConnection;
    @Mock PreparedStatement mockPS;
    @Mock(lenient = true) ResultSet mockRS;

    RawDescriptionRepository repository;

    @SneakyThrows
    @BeforeEach
    void initializeMocks(){
        when(mockPS.executeQuery()).thenReturn(mockRS);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPS);
        when(dataSource.getConnection()).thenReturn(mockConnection);

        repository = new RawDescriptionRepository(dataSource);
    }

    @SneakyThrows
    @Test
    void testInsertRawVulnerability(){
        RawVulnerability testVuln = new RawVulnerability(
                "TestUrl",
                "CVE-0123-4567",
                "2023-01-01 00:00:00",
                "2023-01-01 00:00:00",
                "Test",
                "TestParser"
        );
        testVuln.setSourceType("CNA");

        int insertedCount = repository.insertRawVulnerability(testVuln);

        InOrder inOrder = Mockito.inOrder(mockPS);
        inOrder.verify(mockPS).setString(1, testVuln.getDescription());
        inOrder.verify(mockPS).setString(2, testVuln.getCveId());
        inOrder.verify(mockPS).setTimestamp(3, testVuln.getCreateDate());
        inOrder.verify(mockPS).setTimestamp(4, testVuln.getPublishDate());
        inOrder.verify(mockPS).setTimestamp(5, testVuln.getLastModifiedDate());
        inOrder.verify(mockPS).setString(6, testVuln.getSourceUrl());
        inOrder.verify(mockPS).setString(7, testVuln.getSourceType().type);
        inOrder.verify(mockPS).setString(8, testVuln.getParserType());
        inOrder.verify(mockPS).execute();

        assertThat(insertedCount).isOne();
    }

    @SneakyThrows
    @Test
    void testInsertRawVulnerabilityWithErrors(){
        when(mockPS.execute()).thenThrow(new SQLException());

        RawVulnerability testVuln = new RawVulnerability(
                "TestUrl",
                "CVE-0123-4567",
                "2023-01-01 00:00:00",
                "2023-01-01 00:00:00",
                "Test",
                "TestParser"
        );
        testVuln.setSourceType("CNA");

        int insertedCount = repository.insertRawVulnerability(testVuln);

        InOrder inOrder = Mockito.inOrder(mockPS);
        inOrder.verify(mockPS).setString(1, testVuln.getDescription());
        inOrder.verify(mockPS).setString(2, testVuln.getCveId());
        inOrder.verify(mockPS).setTimestamp(3, testVuln.getCreateDate());
        inOrder.verify(mockPS).setTimestamp(4, testVuln.getPublishDate());
        inOrder.verify(mockPS).setTimestamp(5, testVuln.getLastModifiedDate());
        inOrder.verify(mockPS).setString(6, testVuln.getSourceUrl());
        inOrder.verify(mockPS).setString(7, testVuln.getSourceType().type);
        inOrder.verify(mockPS).setString(8, testVuln.getParserType());
        inOrder.verify(mockPS).setString(9, testVuln.getDomain());
        inOrder.verify(mockPS).execute();

        assertThat(insertedCount).isZero();
    }

    @Nested
    class TestCheckIfInRawDescription {
        String cveId = "CVE-0123-4567";
        String description = "Test";

        @SneakyThrows
        @Test
        void whenEmptyResultSetReturned() {
            when(mockPS.executeQuery()).thenReturn(mockRS);
            when(mockRS.next()).thenReturn(false);
            assertThat(repository.checkIfInRawDescriptions(cveId, description)).isFalse();
        }

        @SneakyThrows
        @Test
        void whenResultSetReturnsZeroCount() {
            when(mockPS.executeQuery()).thenReturn(mockRS);
            when(mockRS.next()).thenReturn(true);
            when(mockRS.getInt("numInRawDesc")).thenReturn(0);
            assertThat(repository.checkIfInRawDescriptions(cveId, description)).isFalse();
        }

        @SneakyThrows
        @Test
        void whenResultSetReturnsOneCount() {
            when(mockPS.executeQuery()).thenReturn(mockRS);
            when(mockRS.next()).thenReturn(true);
            when(mockRS.getInt("numInRawDesc")).thenReturn(1);
            assertThat(repository.checkIfInRawDescriptions(cveId, description)).isTrue();
        }
    }

    @SneakyThrows
    @Test
    public void testCheckIfCveDescriptionNotInRawDescriptions() {
        when(mockPS.executeQuery()).thenReturn(mockRS);
        when(mockRS.next()).thenReturn(false);

        Map<String, LocalDateTime> data = repository.getRawCVEForNVDComparisons();

        assertThat(data).isEmpty();
    }

    @SneakyThrows
    @Test
    public void testGetRawDescriptionForComparisonsNoCves() {
        when(mockPS.executeQuery()).thenReturn(mockRS);
        when(mockRS.next()).thenReturn(false);

        Map<String, LocalDateTime> data = repository.getRawCVEForNVDComparisons();

        assertThat(data).isEmpty();
    }

    @SneakyThrows
    @Test
    public void testGetRawDescriptionForComparisons() {
        String expectedVulnId = "1";
        Timestamp expectedTime = new Timestamp(0);
        when(mockPS.executeQuery()).thenReturn(mockRS);
        when(mockRS.next()).thenReturn(true, false);
        when(mockRS.getString("cve_id")).thenReturn(expectedVulnId);
        when(mockRS.getTimestamp("published_date")).thenReturn(expectedTime);

        Map<String, LocalDateTime> data = repository.getRawCVEForNVDComparisons();

        assertThat(data).containsExactly(entry(expectedVulnId, expectedTime.toLocalDateTime()));
    }

    @Test
    @SneakyThrows
    public void getRawVulnerabilitiesTest() {
        when(mockRS.next()).thenReturn(true, false);

        // Set up the expected data
        String cveId = "CVE-2023-5678";

        // Call the method under test
        Set<RawVulnerability> result = repository.getRawVulnerabilities(cveId);

        // Verify the expected output
        assertEquals(1, result.size());

        // Verify pstmt.setString() call
        verify(mockPS).setString(1, cveId);
    }

    @Test
    @SneakyThrows
    public void markGarbageTest() {

        Set<RawVulnerability> mockedRawVulns = new HashSet<>();
        mockedRawVulns.add(new RawVulnerability(1, "CVE-2021-1234", "Description", null, null, null, ""));
        mockedRawVulns.add(new RawVulnerability(2, "CVE-2021-5678", "Description", null, null, null, ""));

        // Call the updateFilterStatus method
        repository.updateFilterStatus(mockedRawVulns);

        // Verify that pstmt.setInt() is called with the correct arguments
        verify(mockPS, times(2)).setInt(eq(1), eq(1));
        verify(mockPS).setInt(eq(2), eq(1));
        verify(mockPS).setInt(eq(2), eq(2));

        // Verify that pstmt.addBatch() is called for each RawVulnerability
        verify(mockPS, times(2)).addBatch();

        // Verify that pstmt.executeBatch() is called once
        verify(mockPS).executeBatch();
    }

    @Test
    @SneakyThrows
    public void getUsedRawVulnerabilitiesTest() {
        when(mockRS.next()).thenReturn(true, true, false);
        when(mockRS.getInt(anyString())).thenReturn(1,2);
        when(mockRS.getString(anyString())).thenReturn("desc");
        when(mockRS.getTimestamp(anyString())).thenReturn(new Timestamp(System.currentTimeMillis()));

        Set<RawVulnerability> rawVulns = repository.getUsedRawVulnerabilities("cveId");

       verify(mockPS).setString(1, "cveId");

        assertEquals(2, rawVulns.size());

    }
}
