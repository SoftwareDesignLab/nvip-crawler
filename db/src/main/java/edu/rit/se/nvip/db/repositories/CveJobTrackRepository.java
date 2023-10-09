package edu.rit.se.nvip.db.repositories;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;


@Slf4j
@RequiredArgsConstructor
public class CveJobTrackRepository {

    private final DataSource dataSource;

    private final String insertCVEJob = "INSERT INTO cvejobtrack (cve_id) VALUES (?) ";

    /**
     * Add status for CVE in Job Tracker Table
     * @param cveId
     */
    public void addJobForCVE(String cveId) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement pstmt = connection.prepareStatement(insertCVEJob)) {
            pstmt.setString(1, cveId);
            pstmt.executeUpdate();

        } catch (Exception e) {
            log.error("ERROR: Failed to add CVE {} in cvejobtrack table\n{}", cveId, e);
        }

    }

    private final String checkifInJobTrack = "SELECT COUNT(*) numInJobtrack FROM cvejobtrack WHERE cve_id = ?";

    /**
     * Checks if a CVEID is already in cvejobtrack table
     * @param cveId
     * @return
     */
    public boolean isCveInJobTrack(String cveId) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement pstmt = connection.prepareStatement(checkifInJobTrack)) {
            pstmt.setString(1, cveId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next())
                return rs.getInt("numInJobtrack") > 0;
        } catch (Exception e) {
            log.error("ERROR: Failed to check CVE {} in cvejobtrack table\n{}", cveId, e);
        }

        return false;

    }
}
