/ **
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
* /

package edu.rit.se.nvip.db.repositories;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;


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


    private final String getJobs = "SELECT * FROM cvejobtrack";

    /**
     * Gets jobs
     * @return
     */
    public Set<String> getJobs() {
        Set<String> cveIds = new HashSet<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(getJobs)) {
            ResultSet res = pstmt.executeQuery();
            while (res.next()) {
                cveIds.add(res.getString("cve_id"));
            }
        } catch (SQLException ex) {
            log.error("Error retrieving jobs.\n{}", ex);
            return new HashSet<>();
        }
        return cveIds;
    }
}
