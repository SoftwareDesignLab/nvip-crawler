package edu.rit.se.nvip.db.repositories;

import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.db.model.RunStats;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import javax.sql.DataSource;
import java.sql.*;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)class RunHistoryRepositoryTest {

    @Mock
    DataSource dataSource;
    @Mock
    Connection mockConnection;
    @Mock
    PreparedStatement mockPS;
    @Mock(lenient = true)
    ResultSet mockRS;

    RunHistoryRepository repository;

    @SneakyThrows
    @BeforeEach
    void initializeMocks(){
        when(mockPS.executeQuery()).thenReturn(mockRS);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPS);
        when(dataSource.getConnection()).thenReturn(mockConnection);

        repository = new RunHistoryRepository(dataSource);
    }


    @Test
    @SneakyThrows
    public void insertRunTest() {
        Set<CompositeVulnerability> vulns = new HashSet<>();

        CompositeVulnerability vuln1 = new CompositeVulnerability(new RawVulnerability(1, "CVE-1", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));
        vulns.add(vuln1);

        RunStats run = new RunStats(vulns);

        int res = repository.insertRun(run);

        verify(mockPS).setInt(2, 1);
        verify(mockPS).setInt(3, 1);
        verify(mockPS).setInt(4, 0);
        verify(mockPS).setInt(5, 1);
        verify(mockPS).setInt(6, 1);
        verify(mockPS).setInt(7, 1);
        verify(mockPS).setDouble(8, 0);
        verify(mockPS).setDouble(9, 0);

        verify(mockPS).execute();
        assertEquals(1, res);
    }

}