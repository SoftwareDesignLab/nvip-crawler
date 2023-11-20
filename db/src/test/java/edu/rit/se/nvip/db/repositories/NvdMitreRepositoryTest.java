package edu.rit.se.nvip.db.repositories;

import org.junit.Test;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.when;

class NvdMitreRepositoryTest {
    // todo uncomment and fix
//    @Test
//    public void insertTimeGapsForNewVulnsTest() throws SQLException {
//        Set<DeprecatedCompositeVulnerability> compVulns = new HashSet<>();
//        DeprecatedCompositeVulnerability vuln = new DeprecatedCompositeVulnerability(new RawVulnerability(1, "CVE-2023-1111", "desc", offset(-1), offset(1), offset(-10), "example.com"));
//        DeprecatedCompositeVulnerability vuln2 = new DeprecatedCompositeVulnerability(new RawVulnerability(1, "CVE-2023-2222", "desc", offset(-1), offset(1), offset(-10), "example.com"));
//
//        DeprecatedMitreVulnerability mVuln = new DeprecatedMitreVulnerability("cve-1", "Public");
//        DeprecatedNvdVulnerability nVuln = new DeprecatedNvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed", new ArrayList<>());
//
//        vuln.setMitreVuln(mVuln);
//        vuln2.setNvdVuln(nVuln);
//
//        compVulns.add(vuln);
//        compVulns.add(vuln2);
//
//        int res = dbh.insertTimeGapsForNewVulns(compVulns);
//
//        verify(pstmt).setString(1, "CVE-2023-1111");
//        verify(pstmt).setString(1, "CVE-2023-2222");
//        verify(pstmt).setString(2, "nvd");
//        verify(pstmt).setString(2, "mitre");
//        verify(pstmt, times(2)).addBatch();
//        verify(pstmt).executeBatch();
//
//        assertEquals(1, res);
//    }

//    @Test
//    public void attachNvdVulnsTest() throws SQLException {
//        Set<DeprecatedCompositeVulnerability> vulns = new HashSet<>();
//
//        when(res.next()).thenReturn(true, false);
//        when(res.getString(anyString())).thenReturn("CVE-2023-2222", "Analyzed");
//
//        DeprecatedCompositeVulnerability vuln = new DeprecatedCompositeVulnerability(new RawVulnerability(1, "CVE-2023-2222", "desc", offset(-1), offset(1), offset(-10), "example.com"));
//        DeprecatedNvdVulnerability nVuln = new DeprecatedNvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed", new ArrayList<>());
//        vuln.setNvdVuln(nVuln);
//        vuln.setPotentialSources(new HashSet<>());
//        Set<DeprecatedCompositeVulnerability> set = dbh.attachNvdVulns(vulns);
//
//        assertTrue(set.isEmpty());
//
//        vulns.add(vuln);
//
//        set = dbh.attachNvdVulns(vulns);
//
//        verify(pstmt).setString(1, "CVE-2023-2222");
//
//        assertEquals(1, set.size());
//        List<DeprecatedCompositeVulnerability> list = new ArrayList<>(set);
//
//        assertEquals(DeprecatedNvdVulnerability.NvdStatus.ANALYZED, list.get(0).getNvdVuln().getStatus());
//
//    }

//    @Test
//    public void attachMitreVulnsTest() throws SQLException {
//        Set<DeprecatedCompositeVulnerability> vulns = new HashSet<>();
//
//        when(res.next()).thenReturn(true, false);
//        when(res.getString(anyString())).thenReturn("CVE-2023-2222", "Public");
//
//        DeprecatedCompositeVulnerability vuln = new DeprecatedCompositeVulnerability(new RawVulnerability(1, "CVE-2023-2222", "desc", offset(-1), offset(1), offset(-10), "example.com"));
//        DeprecatedMitreVulnerability mVuln = new DeprecatedMitreVulnerability("cve-1", "Public");
//        vuln.setMitreVuln(mVuln);
//        Set<DeprecatedCompositeVulnerability> set = dbh.attachMitreVulns(vulns);
//
//        assertTrue(set.isEmpty());
//
//        vulns.add(vuln);
//
//        set = dbh.attachMitreVulns(vulns);
//
//        verify(pstmt).setString(1, "CVE-2023-2222");
//
//        assertEquals(1, set.size());
//        List<DeprecatedCompositeVulnerability> list = new ArrayList<>(set);
//
//        assertEquals(DeprecatedMitreVulnerability.MitreStatus.PUBLIC, list.get(0).getMitreVuln().getStatus());
//    }



//    @Test
//    public void backfillMitreTimegapsTest() throws SQLException {
//        Set<DeprecatedMitreVulnerability> mitreVulns = new HashSet<>();
//        DeprecatedMitreVulnerability vuln = new DeprecatedMitreVulnerability("cve-1", "Public");
//        DeprecatedMitreVulnerability vuln2 = new DeprecatedMitreVulnerability("cve-2",  "Reserved");
//        mitreVulns.add(vuln);
//        mitreVulns.add(vuln2);
//
//        int res = dbh.backfillMitreTimegaps(mitreVulns);
//
//        verify(pstmt).setString(1, "cve-1");
//        verify(pstmt).setString(1, "cve-2");
//        verify(pstmt, times(2)).addBatch();
//        verify(pstmt).executeBatch();
//
//        assertEquals(1, res);
//
//    }



//    @Test
//    public void upsertMitreDataTest() throws SQLException {
//        Set<DeprecatedMitreVulnerability> mitreVulns = new HashSet<>();
//        DeprecatedMitreVulnerability vuln = new DeprecatedMitreVulnerability("cve-1", "Public");
//        DeprecatedMitreVulnerability vuln2 = new DeprecatedMitreVulnerability("cve-2",  "Reserved");
//        mitreVulns.add(vuln);
//        mitreVulns.add(vuln2);
//
//        when(res.next()).thenReturn(true, false);
//        when(res.getString(1)).thenReturn("cve-1");
//
//        Set<DeprecatedMitreVulnerability> set = dbh.upsertMitreData(mitreVulns);
//
//        verify(pstmt).setString(1, "cve-1");
//        verify(pstmt).setString(1, "cve-2");
//        verify(pstmt).setString(2, "Public");
//        verify(pstmt).setString(2, "Reserved");
//        verify(pstmt, times(2)).addBatch();
//        verify(pstmt).executeBatch();
//
//        assertEquals(1, set.size());
//
//    }

//    @Test
//    public void backfillNvdTimegapsTest() throws SQLException {
//        Set<DeprecatedNvdVulnerability> nvdVulns = new HashSet<>();
//        DeprecatedNvdVulnerability vuln = new DeprecatedNvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed", new ArrayList<>());
//        DeprecatedNvdVulnerability vuln2 = new DeprecatedNvdVulnerability("cve-2", new Timestamp(System.currentTimeMillis()), "Received", new ArrayList<>());
//        nvdVulns.add(vuln);
//        nvdVulns.add(vuln2);
//
//        int res = dbh.backfillNvdTimegaps(nvdVulns);
//
//        verify(pstmt).setString(1, "cve-1");
//        verify(pstmt).setString(1, "cve-2");
//        verify(pstmt, times(2)).addBatch();
//        verify(pstmt).executeBatch();
//
//        assertEquals(1, res);
//    }

//    @Test
//    public void upsertNvdDataTest() throws SQLException {
//        Set<DeprecatedNvdVulnerability> vulns = new HashSet<>();
//        DeprecatedNvdVulnerability vuln = new DeprecatedNvdVulnerability("cve-1", new Timestamp(System.currentTimeMillis()), "Analyzed", new ArrayList<>());
//        DeprecatedNvdVulnerability vuln2 = new DeprecatedNvdVulnerability("cve-2", new Timestamp(System.currentTimeMillis()), "Not in NVD", new ArrayList<>());
//        vulns.add(vuln);
//        vulns.add(vuln2);
//
//        when(res.next()).thenReturn(true, false);
//        when(res.getString(1)).thenReturn("cve-1");
//
//
//        Set<DeprecatedNvdVulnerability> set = dbh.upsertNvdData(vulns);
//
//        verify(pstmt, times(2)).setString(1, "cve-1");
//        verify(pstmt, times(2)).setString(1, "cve-2");
//        verify(pstmt).setString(3, "Analyzed");
//        verify(pstmt).setString(3, "Not in NVD");
//        verify(pstmt, times(2)).addBatch();
//        verify(pstmt, times(2)).executeBatch();
//
//        assertEquals(1, set.size());
//    }

    //    @Test
    //    public void getMitreDataCountTest(){
    //        try {
    //            when(res.next()).thenReturn(true, false);
    //            when(res.getInt(anyString())).thenReturn(0, 1);
    //
    //            boolean result = dbh.isMitreTableEmpty();
    //
    //            assertTrue(result);
    //            result = dbh.isMitreTableEmpty();
    //            assertFalse(result);
    //        } catch (SQLException e) {
    //            throw new RuntimeException(e);
    //        }
    //    }

}