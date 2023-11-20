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
