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