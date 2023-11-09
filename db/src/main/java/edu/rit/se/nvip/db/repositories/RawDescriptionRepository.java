package edu.rit.se.nvip.db.repositories;

import com.google.common.collect.Lists;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.model.RawVulnerability;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


@Slf4j
@RequiredArgsConstructor
public class RawDescriptionRepository {

    private final DataSource dataSource;

    private final String insertRawData = "INSERT INTO rawdescription (raw_description, cve_id, created_date, published_date, last_modified_date, source_url, source_type, parser_type, domain) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    private final String checkIfInRawDesc = "SELECT COUNT(*) numInRawDesc FROM rawdescription WHERE cve_id = ? AND raw_description = ?";
    private final String getRawCVEs = "SELECT DISTINCT cve_id, published_date FROM rawdescription order by cve_id desc";

    /**
     * for inserting crawled data to rawdescriptions
     * @param vuln
     * @return
     */
    public int insertRawVulnerability(RawVulnerability vuln) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement pstmt = connection.prepareStatement(insertRawData);) {

            pstmt.setString(1, vuln.getDescription());
            pstmt.setString(2, vuln.getCveId());
            Timestamp cdate = Timestamp.valueOf(vuln.getCreatedDateAsDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            pstmt.setTimestamp(3, cdate);
            try {
                pstmt.setTimestamp(4, Timestamp.valueOf(vuln.getPublishDateAsDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
            } catch (DateTimeParseException e) {
                log.error("Failed to parse publish date for {}. Insertion will proceed using the created date as the publish date.", vuln.getCveId());
                pstmt.setTimestamp(4, cdate);
            }
            try {
                pstmt.setTimestamp(5, Timestamp.valueOf(vuln.getLastModifiedDateAsDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
            } catch (DateTimeParseException e) {
                log.error("Failed to parse last modified date for {}. Insertion will proceed with a null last modified date.", vuln.getCveId());
                pstmt.setTimestamp(5, null);
            }
            pstmt.setString(6, vuln.getSourceURL());
            pstmt.setString(7, vuln.getSourceType());
            pstmt.setString(8, vuln.getParserType());
            pstmt.setString(9, vuln.getDomain());

            pstmt.execute();

            return 1;
        } catch (Exception e) {
            log.error("ERROR: Failed to insert data for CVE {} (sourceURL: {}) into rawdescription table\n{}", vuln.getCveId(), vuln.getSourceURL(), e);
        }

        return 0;
    }

    /**
     * for inserting crawled data to rawdescriptions
     * @param vulns
     * @return
     */
    public List<RawVulnerability> batchInsertRawVulnerability(List<RawVulnerability> vulns) {
        List<RawVulnerability> inserted = new ArrayList<>();

        try (Connection connection = dataSource.getConnection();
             PreparedStatement pstmt = connection.prepareStatement(insertRawData)) {

            //Split vulns into batches for JDBC Insert
            //TODO: Move the hardcoded value
            for(List<RawVulnerability> batch: Lists.partition(vulns, 256)) {
                List<RawVulnerability> submittedVulns = new ArrayList<>();
                for(RawVulnerability vuln: batch) {
                    try {
                        pstmt.setString(1, vuln.getDescription());
                        pstmt.setString(2, vuln.getCveId());
                        Timestamp cdate = Timestamp.valueOf(vuln.getCreatedDateAsDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                        pstmt.setTimestamp(3, cdate);
                        try {
                            pstmt.setTimestamp(4, Timestamp.valueOf(vuln.getPublishDateAsDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
                        } catch (DateTimeParseException e) {
                            log.error("Failed to parse publish date for {}. Insertion will proceed using the created date as the publish date.", vuln.getCveId());
                            pstmt.setTimestamp(4, cdate);
                        }
                        try {
                            pstmt.setTimestamp(5, Timestamp.valueOf(vuln.getLastModifiedDateAsDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
                        } catch (DateTimeParseException e) {
                            log.error("Failed to parse last modified date for {}. Insertion will proceed with a null last modified date.", vuln.getCveId());
                            pstmt.setTimestamp(5, null);
                        }
                        pstmt.setString(6, vuln.getSourceURL());
                        pstmt.setString(7, vuln.getSourceType());
                        pstmt.setString(8, vuln.getParserType());
                        pstmt.setString(9, vuln.getDomain());
                        pstmt.addBatch();
                        submittedVulns.add(vuln);
                    } catch (DateTimeParseException e) {
                        log.error("Failed to add {} to batch: {}", vuln.getCveId(), e.getMessage());
                        log.error("", e);
                    }
                }
                int[] results;
                try {
                    results = pstmt.executeBatch();
                } catch (BatchUpdateException e) {
                    // we expect this exception to realistically happen for every batch because a batch will likely contain a CVE that matches an existing CVE in the database
                    // where "matching" means it violates the (cve_id, description_hash, domain) uniqueness constraint.
                    // technically it could be caused by other insertion errors, but we have no way of distinguishing them with this setup
                    results = e.getUpdateCounts();
                }

                log.info("Size of submittedVulns: {} - Size of results: {}", submittedVulns.size(), results.length);
                int i = 0;
                for(RawVulnerability vuln: submittedVulns) {
                    if (results.length == 0) {
                        break;
                    }
                    if (results[i] == Statement.SUCCESS_NO_INFO || results[i] == Statement.KEEP_CURRENT_RESULT || results[i] == Statement.CLOSE_CURRENT_RESULT) {
                        inserted.add(vuln);
                    } else {
                        log.info("Failed to insert {}: {}", vulns.get(i).getCveId(), results[i]);
                    }
                    i++;
                }
                pstmt.clearBatch();
            }
        } catch (SQLException e) {
            log.error("Failed to execute batch insert");
            log.error(e.toString());
        } catch (Exception e) {
            log.error("Unexpected Error Occurred!");
            log.error("", e);
        }

        return inserted;
    }

    /**
     * For checking if a description is already in rawdescription
     * Compares descriptions for now
     * @return
     */
    public boolean checkIfInRawDescriptions(String cveId, String description) {

        try (Connection connection = dataSource.getConnection();
             PreparedStatement pstmt = connection.prepareStatement(checkIfInRawDesc)) {
            pstmt.setString(1, cveId);
            pstmt.setString(2, description);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next())
                return rs.getInt("numInRawDesc") > 0;
        } catch (Exception e) {
            log.error("ERROR: Failed to check description {} in rawdescription table\n{}", description, e);
        }

        return false;

    }

    /**
     * For getting raw CVE Data for NVD Comparison
     * @return
     */
    public HashMap<String, LocalDateTime> getRawCVEForNVDComparisons() {

        HashMap<String, LocalDateTime> rawCves = new HashMap<>();

        try (Connection connection = dataSource.getConnection();
             PreparedStatement pstmt = connection.prepareStatement(getRawCVEs)) {
            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {
                rawCves.put(rs.getString("cve_id"), rs.getTimestamp("published_date").toLocalDateTime());
            }
        } catch (Exception e) {
            log.error("ERROR: Failed to grab raw CVEs from rawdescription table\n{}", e);
        }

        return rawCves;
    }

    public static void main(String[] args) {
        List<RawVulnerability> list = new ArrayList<>();
        RawDescriptionRepository repo = new RawDescriptionRepository(DatabaseHelper.getInstance().getDataSource());

        List<RawVulnerability> singleList = new ArrayList<>();
        singleList.add(new RawVulnerability("http://url.gov/page/0", "CVE-1234", "01/01/2023", null, "description", "generic"));
        singleList.forEach(r->r.setSourceType("cna"));

        list.add(new RawVulnerability("http://url.gov/page/1", "CVE-6666", "not a date", null, "description", "generic"));
        list.add(new RawVulnerability("http://url.gov/page/2", "CVE-7777", "not a date", null, "description", "generic"));
        list.add(new RawVulnerability("http://url.gov/page/1", "CVE-8888", "not a date", null, "description", "generic"));
        list.add(new RawVulnerability("http://url.gov/page/1", "CVE-9999", "not a date", null, "description", "generic"));
        list.forEach(r->r.setSourceType("cna"));

        List<RawVulnerability> singleInsert = repo.batchInsertRawVulnerability(singleList);
        System.out.println(singleInsert.size());

        List<RawVulnerability> inserted = repo.batchInsertRawVulnerability(list);
        System.out.println(inserted.size());
    }
}
