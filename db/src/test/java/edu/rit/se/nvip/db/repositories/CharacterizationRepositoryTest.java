package edu.rit.se.nvip.db.repositories;

import static org.junit.jupiter.api.Assertions.*;

class CharacterizationRepositoryTest {
    // todo uncommment and fix these tests

//    @org.junit.Test
//    public void insertVdoSetAndCvssTest() throws SQLException {
//        Set<DeprecatedCompositeVulnerability> vulns = new HashSet<>();
//
//        DeprecatedCompositeVulnerability vuln1 = new DeprecatedCompositeVulnerability(new RawVulnerability(1, "CVE-1", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));
//        DeprecatedCompositeVulnerability vuln2 = new DeprecatedCompositeVulnerability(new RawVulnerability(1, "CVE-2", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));
//
//        vuln1.addVdoCharacteristic(new VdoCharacteristic(vuln1.getCveId(), VDOLabel.LOCAL, 1.0));
//        vuln2.addVdoCharacteristic(new VdoCharacteristic(vuln2.getCveId(), VDOLabel.LOCAL, 1.0));
//
//        vulns.add(vuln1);
//        vulns.add(vuln2);
//
//
//        int res = dbh.insertVdoCvssBatch(vulns);
//
//        verify(conn).setAutoCommit(false);
//        verify(pstmt, times(2)).executeUpdate();
//        verify(pstmt, times(2)).addBatch();
//        verify(pstmt, times(2)).setString(1, vuln1.getVdoCharacteristics().get(0).getCveId());
//        verify(pstmt, times(2)).setString(2, vuln1.getVdoCharacteristics().get(0).getVdoLabel().vdoLabelName);
//        verify(pstmt, times(2)).setString(3, vuln1.getVdoCharacteristics().get(0).getVdoNounGroup().vdoNameForUI);
//        verify(pstmt, times(2)).setDouble(4, 1.0);
//        verify(pstmt).executeBatch();
//        verify(conn).commit();
//
//        assertEquals(1, res);
//    }

}