package edu.rit.se.nvip.db.repositories;

import org.junit.Test;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;

class RunHistoryRepositoryTest {
    //todo convert this old test to match new approach
//    @Test
//    public void insertRunTest() throws SQLException {
//        Set<CompositeVulnerability> vulns = new HashSet<>();
//
//        CompositeVulnerability vuln1 = new CompositeVulnerability(new RawVulnerability(1, "CVE-1", "desc", new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "ex.com"));
//        vulns.add(vuln1);
//
//        RunStats run = new RunStats(vulns);
//
//        int res = dbh.insertRun(run);
//
//        verify(pstmt).setInt(2, 1);
//        verify(pstmt).setInt(3, 1);
//        verify(pstmt).setInt(4, 0);
//        verify(pstmt).setInt(5, 1);
//        verify(pstmt).setInt(6, 1);
//        verify(pstmt).setInt(7, 1);
//        verify(pstmt).setDouble(8, 0);
//        verify(pstmt).setDouble(9, 0);
//
//        verify(pstmt).execute();
//        assertEquals(1, res);
//    }

}