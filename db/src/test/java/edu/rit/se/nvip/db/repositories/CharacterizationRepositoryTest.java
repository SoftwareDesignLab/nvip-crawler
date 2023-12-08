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
import edu.rit.se.nvip.db.model.CvssScore;
import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.db.model.VdoCharacteristic;
import edu.rit.se.nvip.db.model.enums.VDOLabel;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class CharacterizationRepositoryTest {

    @Mock
    DataSource dataSource;
    @Mock
    Connection mockConnection;
    @Mock
    PreparedStatement mockPS;
    @Mock
    ResultSet mockRS;

    CharacterizationRepository repository;

    @SneakyThrows
    @BeforeEach
    void initializeMocks(){
        when(mockPS.executeQuery()).thenReturn(mockRS);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPS);
        when(dataSource.getConnection()).thenReturn(mockConnection);

        repository = new CharacterizationRepository(dataSource);
    }

    @Test
    @SneakyThrows
    public void insertVdoSetAndCvssTest()  {
        Set<CompositeVulnerability> vulns = new HashSet<>();

        CompositeVulnerability vuln1 = new CompositeVulnerability(new RawVulnerability(1, "CVE-1", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));
        CompositeVulnerability vuln2 = new CompositeVulnerability(new RawVulnerability(1, "CVE-2", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));

        vuln1.addVdoCharacteristic(new VdoCharacteristic(vuln1.getCveId(), VDOLabel.LOCAL, 1.0));
        vuln1.addCvssScore(new CvssScore("CVE-1", 0.5, 0.3));
        vuln2.addVdoCharacteristic(new VdoCharacteristic(vuln2.getCveId(), VDOLabel.LOCAL, 1.0));
        vuln2.addCvssScore(new CvssScore("CVE-2", 0.5, 0.3));

        vulns.add(vuln1);
        vulns.add(vuln2);

        when(mockConnection.prepareStatement(anyString(), eq(Statement.RETURN_GENERATED_KEYS))).thenReturn(mockPS);
        when(mockPS.getGeneratedKeys()).thenReturn(mockRS);

        int res = repository.insertVdoCvssBatch(vulns);

        verify(mockConnection, times(2)).setAutoCommit(false);
        verify(mockPS, times(4)).executeUpdate();
        verify(mockPS, times(2)).addBatch();
        verify(mockPS, times(2)).setString(1, vuln1.getVdoCharacteristics().get(0).getCveId());
        verify(mockPS, times(2)).setString(2, vuln1.getVdoCharacteristics().get(0).getVdoLabel().vdoLabelName);
        verify(mockPS, times(2)).setString(3, vuln1.getVdoCharacteristics().get(0).getVdoNounGroup().vdoNameForUI);
        verify(mockPS, times(2)).setDouble(4, 1.0);
        verify(mockPS, times(2)).executeBatch();
        verify(mockConnection, times(2)).commit();

        assertEquals(1, res);
    }

}