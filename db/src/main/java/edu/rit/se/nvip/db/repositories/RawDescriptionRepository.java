package edu.rit.se.nvip.db.repositories;

import com.google.common.collect.Lists;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.model.CompositeDescription;
import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.RawVulnerability;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.*;


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
            pstmt.setTimestamp(3, vuln.getCreateDate());
            pstmt.setTimestamp(4, vuln.getPublishDate());
            pstmt.setTimestamp(5, vuln.getLastModifiedDate());
            pstmt.setString(6, vuln.getSourceUrl());
            pstmt.setString(7, vuln.getSourceType().type);
            pstmt.setString(8, vuln.getParserType());
            pstmt.setString(9, vuln.getDomain());

            pstmt.execute();

            return 1;
        } catch (Exception e) {
            log.error("ERROR: Failed to insert data for CVE {} (sourceURL: {}) into rawdescription table\n{}", vuln.getCveId(), vuln.getSourceUrl(), e);
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
                        pstmt.setTimestamp(3, vuln.getCreateDate());
                        pstmt.setTimestamp(4, vuln.getPublishDate());
                        pstmt.setTimestamp(5, vuln.getLastModifiedDate());
                        pstmt.setString(6, vuln.getSourceUrl());
                        pstmt.setString(7, vuln.getSourceType().type);
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


    private final String getRawVulnByCveId = "SELECT * FROM rawdescription WHERE cve_id = ?";

    /**
     * Gets a set of Raw Vulnerabilities
     * @param cveId
     * @return
     */
    public Set<RawVulnerability> getRawVulnerabilities(String cveId) {
        Set<RawVulnerability> rawVulns = new HashSet<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(getRawVulnByCveId)) {
            pstmt.setString(1, cveId);
            ResultSet res = pstmt.executeQuery();
            while (res.next()) {
                RawVulnerability rawVuln = new RawVulnerability(
                        res.getInt("raw_description_id"),
                        res.getString("cve_id"),
                        res.getString("raw_description"),
                        res.getTimestamp("published_date"),
                        res.getTimestamp("last_modified_date"),
                        res.getTimestamp("published_date"),
                        res.getString("source_url"),
                        res.getString("source_type"),
                        res.getInt("is_garbage")
                );
                rawVulns.add(rawVuln);
            }
        } catch (SQLException ex) {
            log.error("Error retrieving rawdescriptions.\n{}", ex);
            return new HashSet<>();
        }
        return rawVulns;
    }

    private String updateFilterStatus = "UPDATE rawdescription SET is_garbage = ? WHERE raw_description_id = ?";

    public void updateFilterStatus(Set<RawVulnerability> rawVulns) {
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(updateFilterStatus)) {
            for (RawVulnerability vuln : rawVulns) {
                pstmt.setInt(1, vuln.getFilterStatus().value);
                pstmt.setInt(2, vuln.getId());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        } catch (SQLException ex) {
            log.error("Error marking rawdescriptions as garbage.\n{}", ex);
        }
    }

    private String getUsedRawVulns = "SELECT rd.* " +
            "FROM vulnerability AS v " +
            "INNER JOIN vulnerabilityversion AS vv ON v.vuln_version_id = vv.vuln_version_id " +
            "INNER JOIN description AS d ON vv.description_id = d.description_id " +
            "INNER JOIN rawdescriptionjt AS rdjt ON d.description_id = rdjt.description_id " +
            "INNER JOIN rawdescription AS rd ON rdjt.raw_description_id = rd.raw_description_id " +
            "WHERE v.cve_id = ?";

    public Set<RawVulnerability> getUsedRawVulnerabilities(String cveId) {
        Set<RawVulnerability> rawVulns = new HashSet<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(getUsedRawVulns)) {
            pstmt.setString(1, cveId);
            ResultSet res = pstmt.executeQuery();
            while (res.next()) {
                RawVulnerability rawVuln = new RawVulnerability(
                        res.getInt("raw_description_id"),
                        res.getString("cve_id"),
                        res.getString("raw_description"),
                        res.getTimestamp("published_date"),
                        res.getTimestamp("last_modified_date"),
                        res.getTimestamp("published_date"),
                        res.getString("source_url"),
                        res.getString("source_type"),
                        res.getInt("is_garbage")
                );
                rawVulns.add(rawVuln);
            }
        } catch (SQLException ex) {
            log.error("Error retrieving used rawdescriptions with cve_id {}.\n{}", cveId, ex);
            return new HashSet<>();
        }
        return rawVulns;
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
