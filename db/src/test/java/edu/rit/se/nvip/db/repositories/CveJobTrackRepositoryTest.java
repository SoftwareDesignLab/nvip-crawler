package edu.rit.se.nvip.db.repositories;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.sql.DataSource;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
public class CveJobTrackRepositoryTest {

    @Mock DataSource dataSource;
    @Mock Connection mockConnection;
    @Mock PreparedStatement mockPS;

    CveJobTrackRepository repository;

    @SneakyThrows
    @BeforeEach
    void initializeMocks(){
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
}
