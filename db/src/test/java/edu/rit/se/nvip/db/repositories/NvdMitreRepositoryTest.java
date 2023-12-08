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
import edu.rit.se.nvip.db.model.MitreVulnerability;
import edu.rit.se.nvip.db.model.NvdVulnerability;
import edu.rit.se.nvip.db.model.RawVulnerability;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import javax.sql.DataSource;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class NvdMitreRepositoryTest {
    @Mock
    DataSource dataSource;
    @Mock
    Connection mockConnection;
    @Mock
    PreparedStatement mockPS;
    @Mock
    ResultSet mockRS;

    NvdMitreRepository repository;


    @SneakyThrows
    @BeforeEach
    void initializeMocks(){
        when(mockPS.executeQuery()).thenReturn(mockRS);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPS);
        when(dataSource.getConnection()).thenReturn(mockConnection);

        repository = new NvdMitreRepository(dataSource);
    }

    // helper field and func for timestamp checks
    private final long dummyMillis = System.currentTimeMillis();
    private Timestamp offset(int nHours) {
        return new Timestamp(dummyMillis + nHours*3600L*1000);
    }
    @Test
    @SneakyThrows
    public void insertTimeGapsForNewVulnsTest() {
        Set<CompositeVulnerability> compVulns = new HashSet<>();
        CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, "CVE-2023-1111", "desc", offset(-1), offset(1), offset(-10), "example.com"));
        CompositeVulnerability vuln2 = new CompositeVulnerability(new RawVulnerability(1, "CVE-2023-2222", "desc", offset(-1), offset(1), offset(-10), "example.com"));

        MitreVulnerability mVuln = new MitreVulnerability("cve-1", "Public");
        NvdVulnerability nVuln = new NvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed", new ArrayList<>());

        vuln.setMitreVuln(mVuln);
        vuln2.setNvdVuln(nVuln);

        compVulns.add(vuln);
        compVulns.add(vuln2);

        int res = repository.insertTimeGapsForNewVulns(compVulns);

        verify(mockPS).setString(1, "CVE-2023-1111");
        verify(mockPS).setString(1, "CVE-2023-2222");
        verify(mockPS).setString(2, "nvd");
        verify(mockPS).setString(2, "mitre");
        verify(mockPS, times(2)).addBatch();
        verify(mockPS).executeBatch();

        Assertions.assertEquals(1, res);
    }

    @Test
    @SneakyThrows
    public void attachNvdVulnsTest() throws SQLException {
        Set<CompositeVulnerability> vulns = new HashSet<>();

        when(mockRS.next()).thenReturn(true, false);
        when(mockRS.getString(anyString())).thenReturn("CVE-2023-2222", "Analyzed");

        CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, "CVE-2023-2222", "desc", offset(-1), offset(1), offset(-10), "example.com"));
        NvdVulnerability nVuln = new NvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed", new ArrayList<>());
        vuln.setNvdVuln(nVuln);
        vuln.setPotentialSources(new HashSet<>());
        Set<CompositeVulnerability> set = repository.attachNvdVulns(vulns);

        assertTrue(set.isEmpty());

        vulns.add(vuln);

        set = repository.attachNvdVulns(vulns);

        verify(mockPS).setString(1, "CVE-2023-2222");

        assertEquals(1, set.size());
        List<CompositeVulnerability> list = new ArrayList<>(set);

        assertEquals(NvdVulnerability.NvdStatus.ANALYZED, list.get(0).getNvdVuln().getStatus());

    }

    @Test
    @SneakyThrows
    public void attachMitreVulnsTest() throws SQLException {
        Set<CompositeVulnerability> vulns = new HashSet<>();

        when(mockRS.next()).thenReturn(true, false);
        when(mockRS.getString(anyString())).thenReturn("CVE-2023-2222", "Public");

        CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, "CVE-2023-2222", "desc", offset(-1), offset(1), offset(-10), "example.com"));
        MitreVulnerability mVuln = new MitreVulnerability("cve-1", "Public");
        vuln.setMitreVuln(mVuln);
        Set<CompositeVulnerability> set = repository.attachMitreVulns(vulns);

        assertTrue(set.isEmpty());

        vulns.add(vuln);

        set = repository.attachMitreVulns(vulns);

        verify(mockPS).setString(1, "CVE-2023-2222");

        assertEquals(1, set.size());
        List<CompositeVulnerability> list = new ArrayList<>(set);

        assertEquals(MitreVulnerability.MitreStatus.PUBLIC, list.get(0).getMitreVuln().getStatus());
    }



    @Test
    @SneakyThrows
    public void backfillMitreTimegapsTest() throws SQLException {
        Set<MitreVulnerability> mitreVulns = new HashSet<>();
        MitreVulnerability vuln = new MitreVulnerability("cve-1", "Public");
        MitreVulnerability vuln2 = new MitreVulnerability("cve-2",  "Reserved");
        mitreVulns.add(vuln);
        mitreVulns.add(vuln2);

        int res = repository.backfillMitreTimegaps(mitreVulns);

        verify(mockPS).setString(1, "cve-1");
        verify(mockPS).setString(1, "cve-2");
        verify(mockPS, times(2)).addBatch();
        verify(mockPS).executeBatch();

        assertEquals(1, res);

    }



    @Test
    @SneakyThrows
    public void upsertMitreDataTest() throws SQLException {
        Set<MitreVulnerability> mitreVulns = new HashSet<>();
        MitreVulnerability vuln = new MitreVulnerability("cve-1", "Public");
        MitreVulnerability vuln2 = new MitreVulnerability("cve-2",  "Reserved");
        mitreVulns.add(vuln);
        mitreVulns.add(vuln2);

        when(mockRS.next()).thenReturn(true, false);
        when(mockRS.getString(1)).thenReturn("cve-1");

        Set<MitreVulnerability> set = repository.upsertMitreData(mitreVulns);

        verify(mockPS).setString(1, "cve-1");
        verify(mockPS).setString(1, "cve-2");
        verify(mockPS).setString(2, "Public");
        verify(mockPS).setString(2, "Reserved");
        verify(mockPS, times(2)).addBatch();
        verify(mockPS).executeBatch();

        assertEquals(1, set.size());

    }

    @Test
    @SneakyThrows
    public void backfillNvdTimegapsTest() throws SQLException {
        Set<NvdVulnerability> nvdVulns = new HashSet<>();
        NvdVulnerability vuln = new NvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed", new ArrayList<>());
        NvdVulnerability vuln2 = new NvdVulnerability("cve-2", new Timestamp(System.currentTimeMillis()), "Received", new ArrayList<>());
        nvdVulns.add(vuln);
        nvdVulns.add(vuln2);

        int res = repository.backfillNvdTimegaps(nvdVulns);

        verify(mockPS).setString(1, "cve-1");
        verify(mockPS).setString(1, "cve-2");
        verify(mockPS, times(2)).addBatch();
        verify(mockPS).executeBatch();

        assertEquals(1, res);
    }

    @Test
    @SneakyThrows
    public void upsertNvdDataTest() throws SQLException {
        Set<NvdVulnerability> vulns = new HashSet<>();
        NvdVulnerability vuln = new NvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed", new ArrayList<>());
        NvdVulnerability vuln2 = new NvdVulnerability("cve-2", new Timestamp(System.currentTimeMillis()), "Not in NVD", new ArrayList<>());
        vulns.add(vuln);
        vulns.add(vuln2);

        when(mockRS.next()).thenReturn(true, false);
        when(mockRS.getString(1)).thenReturn("cve-1");


        Set<NvdVulnerability> set = repository.upsertNvdData(vulns);

        verify(mockPS, times(2)).setString(1, "cve-1");
        verify(mockPS, times(2)).setString(1, "cve-2");
        verify(mockPS).setString(3, "Analyzed");
        verify(mockPS).setString(3, "Not in NVD");
        verify(mockPS, times(2)).addBatch();
        verify(mockPS, times(2)).executeBatch();

        assertEquals(1, set.size());
    }

        @Test
        @SneakyThrows
        public void getMitreDataCountTest(){
            when(mockRS.next()).thenReturn(true, false);
            when(mockRS.getInt(anyString())).thenReturn(0, 1);

            boolean result = repository.isMitreTableEmpty();

            assertTrue(result);
            result = repository.isMitreTableEmpty();
            assertFalse(result);
        }

}