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


import edu.rit.se.nvip.db.model.RunStats;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

@Slf4j
@RequiredArgsConstructor
public class RunHistoryRepository {
    private final DataSource dataSource;

    private static final String INSERT_RUN_STATS = "INSERT INTO runhistory (run_date_time, total_cve_count, new_cve_count, updated_cve_count, not_in_nvd_count, not_in_mitre_count, not_in_both_count, avg_time_gap_nvd, avg_time_gap_mitre)" +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";


    public int insertRun(RunStats run) {
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(INSERT_RUN_STATS)) {
            populateDailyRunInsert(pstmt, run);
            pstmt.execute();
            return 1;
        } catch (SQLException e) {
            log.error("Failed to insert the the run statistics\n{}", e.toString());
            return 0;
        }
    }

    private void populateDailyRunInsert(PreparedStatement pstmt, RunStats run) throws SQLException {
        pstmt.setTimestamp(1, run.getRunDateTime());
        pstmt.setInt(2, run.getTotalCveCount());
        pstmt.setInt(3, run.getNewCveCount());
        pstmt.setInt(4, run.getUpdatedCveCount());
        pstmt.setInt(5, run.getNotInNvdCount());
        pstmt.setInt(6, run.getNotInMitreCount());
        pstmt.setInt(7, run.getNotInBothCount());
        pstmt.setDouble(8, run.getAvgTimeGapNvd());
        pstmt.setDouble(9, run.getAvgTimeGapMitre());
    }
}
