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
import edu.rit.se.nvip.db.model.NvdVulnerability;
import edu.rit.se.nvip.db.model.MitreVulnerability;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Slf4j
@RequiredArgsConstructor
public class NvdMitreRepository {

    private final DataSource dataSource;

    private static final String UPSERT_NVD = "INSERT INTO nvddata (cve_id, published_date, status, last_modified) VALUES (?, ?, ?, NOW()) AS input " +
            "ON DUPLICATE KEY UPDATE " +
            "status = input.status, " +
            "last_modified = IF(input.status <> nvddata.status, NOW(), nvddata.last_modified)";
    private static final String INSERT_NVD_SOURCE_URLS = "INSERT INTO nvdsourceurl (cve_id, source_url) VALUES (?, ?) AS input " +
            "ON DUPLICATE KEY UPDATE " +
            "cve_id = input.cve_id";
    private static final String SELECT_NVD_BY_DATE = "SELECT cve_id FROM nvddata WHERE last_modified >= DATE_SUB(NOW(), INTERVAL 2 MINUTE)";


    public Set<NvdVulnerability> upsertNvdData(Set<NvdVulnerability> nvdCves) {
        List<NvdVulnerability> nvdVulnList = new ArrayList<>(nvdCves); // need order
        Set<NvdVulnerability> toBackfill = new HashSet<>(); // inserts and nontrivial updates

        Map<String, NvdVulnerability> idToVuln = new HashMap<>();
        nvdCves.forEach(v->idToVuln.put(v.getCveId(), v));

        try (Connection conn = dataSource.getConnection();
             PreparedStatement upsertStmt = conn.prepareStatement(UPSERT_NVD);
             PreparedStatement insertSourceUrlsStmt = conn.prepareStatement(INSERT_NVD_SOURCE_URLS);
             PreparedStatement selectStmt = conn.prepareStatement(SELECT_NVD_BY_DATE)) {
            conn.setAutoCommit(false);
            // insert/update all the nvd vulns
            for (NvdVulnerability vuln : nvdVulnList) {
                upsertStmt.setString(1, vuln.getCveId());
                upsertStmt.setTimestamp(2, vuln.getPublishDate());
                upsertStmt.setString(3, vuln.getStatus().toString());
                upsertStmt.addBatch();
                final List<String> sourceUrls = vuln.getSourceUrls();
                insertSourceUrlsStmt.setString(1, vuln.getCveId());
                for (String source : sourceUrls) {
                    insertSourceUrlsStmt.setString(2, source);
                    insertSourceUrlsStmt.addBatch();
                }
            }
            upsertStmt.executeBatch();
            insertSourceUrlsStmt.executeBatch();
            // identify which ones actually were inserted/changed and are "in nvd" by grabbing all modified within last 10 minutes
            ResultSet res = selectStmt.executeQuery();
            while (res.next()) {
                NvdVulnerability vuln = idToVuln.get(res.getString(1));
                if (vuln.inNvd()) {
                    toBackfill.add(vuln);
                }
            }
            conn.commit();
        } catch (SQLException ex) {
            log.error("Error while updating nvddata table.\n{}", ex);
        }
        return toBackfill;
    }
    private static final String UPSERT_MITRE = "INSERT INTO mitredata (cve_id, status, last_modified) VALUES (?, ?, NOW()) AS input " +
            "ON DUPLICATE KEY UPDATE " +
            "status = input.status, " +
            "last_modified = IF(input.status <> mitredata.status, NOW(), mitredata.last_modified)";
    private static final String SELECT_MITRE_BY_DATE = "SELECT cve_id FROM mitredata WHERE last_modified >= DATE_SUB(NOW(), INTERVAL 2 MINUTE)";


    public Set<MitreVulnerability> upsertMitreData(Set<MitreVulnerability> mitreCves) {
        List<MitreVulnerability> mitreVulnList = new ArrayList<>(mitreCves); // need order
        Set<MitreVulnerability> toBackfill = new HashSet<>(); // inserts and nontrivial updates

        Map<String, MitreVulnerability> idToVuln = new HashMap<>();
        mitreCves.forEach(v->idToVuln.put(v.getCveId(), v));

        try (Connection conn = dataSource.getConnection();
             PreparedStatement upsertStmt = conn.prepareStatement(UPSERT_MITRE);
             PreparedStatement selectStmt = conn.prepareStatement(SELECT_MITRE_BY_DATE)) {
            conn.setAutoCommit(false);
            // insert/update all the mitre vulns
            for (MitreVulnerability vuln : mitreVulnList) {
                upsertStmt.setString(1, vuln.getCveId());
                upsertStmt.setString(2, vuln.getStatus().toString());
                upsertStmt.addBatch();
            }
            upsertStmt.executeBatch();
            // identify which ones actually were inserted/changed and are "in mitre"
            ResultSet res = selectStmt.executeQuery();
            while (res.next()) {
                MitreVulnerability vuln = idToVuln.get(res.getString(1));
                if (vuln.inMitre()) {
                    toBackfill.add(vuln);
                }
            }
            conn.commit();
        } catch (SQLException ex) {
            log.error("Error while updating mitredata table.\n{}", ex);
        }
        return toBackfill;
    }

    private static final String MITRE_COUNT = "SELECT COUNT(*) AS num_rows FROM mitredata;";
    public boolean isMitreTableEmpty() {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement upsertStatement = conn.prepareStatement(MITRE_COUNT);
             ResultSet resultSet = upsertStatement.executeQuery()) {

            if (resultSet.next()) {
                int rowCount = resultSet.getInt("num_rows");
                return rowCount == 0;
            } else {
                // This means no rows were returned by the query (something unexpected happened).
                log.error("ERROR: No result returned from the query.");
                return false;
            }
        } catch (SQLException e) {
            log.error("ERROR: Failed to get the amount of rows for mitredata table, {}", e.getMessage());
            return false;
        }
    }

    private static final String BACKFILL_NVD_TIMEGAPS = "INSERT INTO timegap (cve_id, location, timegap, created_date) " +
            "SELECT v.cve_id, 'nvd', TIMESTAMPDIFF(HOUR, v.created_date, n.published_date), NOW() " +
            "FROM nvddata AS n INNER JOIN vulnerability AS v ON n.cve_id = v.cve_id WHERE v.cve_id = ? " +
            "ON DUPLICATE KEY UPDATE cve_id = v.cve_id";
    private static final String BACKFILL_MITRE_TIMEGAPS = "INSERT INTO timegap (cve_id, location, timegap, created_date) " +
            "SELECT v.cve_id, 'mitre', TIMESTAMPDIFF(HOUR, v.created_date, NOW()), NOW() " +
            "FROM mitredata AS m INNER JOIN vulnerability AS v ON m.cve_id = v.cve_id WHERE v.cve_id = ?  " +
            "ON DUPLICATE KEY UPDATE cve_id = v.cve_id";


    public int backfillNvdTimegaps(Set<NvdVulnerability> newNvdVulns) {
        // we don't need to compute time gaps ourselves
        // at this point these nvd vulns should already be in the nvddata table and we have create dates for all vulns in our system
        // so we can compute the timestamp difference within sql, and the inner join ensures this only happens for vulns we already have
        // the (cve_id, location) pair is a key in this table, so the last clause stops any duplicate time gaps
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(BACKFILL_NVD_TIMEGAPS)) {
            for (NvdVulnerability vuln : newNvdVulns) {
                pstmt.setString(1, vuln.getCveId());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
            return 1;
        } catch (SQLException ex) {
            log.error("Error while inserting time gaps.\n{}", ex);
            return 0;
        }
    }

    public int backfillMitreTimegaps(Set<MitreVulnerability> newNvdVulns) {
        // mitre vulns don't have publish dates - so we're using NOW as their "publish date" to compute time gaps until further notice
        // the (cve_id, location) pair is a key in this table, so the last clause stops any duplicate time gaps
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(BACKFILL_MITRE_TIMEGAPS)) {
            for (MitreVulnerability vuln : newNvdVulns) {
                pstmt.setString(1, vuln.getCveId());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
            return 1;
        } catch (SQLException ex) {
            log.error("Error while inserting time gaps.\n{}", ex);
            return 0;
        }
    }

    public int insertTimeGapsForNewVulns(Set<CompositeVulnerability> vulns) {
        String query = "INSERT INTO timegap (cve_id, location, timegap, created_date) VALUES (?, ?, ?, NOW())";
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(query)) {
            for (CompositeVulnerability vuln : vulns) {
                if (vuln.getReconciliationStatus() != CompositeVulnerability.ReconciliationStatus.NEW) {
                    continue; // we should only be putting in time gaps for new vulns. old ones get time gaps when nvddata/mitredata tables are updated
                }
                if (vuln.isInNvd()) {
                    pstmt.setString(1, vuln.getCveId());
                    pstmt.setString(2, "nvd");
                    pstmt.setDouble(3, vuln.getNvdTimeGap());
                    pstmt.addBatch();
                }
                if (vuln.isInMitre()) { // purposely not an "else" - we very well might want to insert 2 time gaps
                    pstmt.setString(1, vuln.getCveId());
                    pstmt.setString(2, "mitre");
                    pstmt.setDouble(3, vuln.getMitreTimeGap());
                    pstmt.addBatch();
                }
            }
            pstmt.executeBatch();
            return 1;
        } catch (SQLException ex) {
            log.error("Error while inserting time gaps for newly discovered vulnerabilities.\n{}", ex);
            return 0;
        }
    }

    public Set<CompositeVulnerability> attachNvdVulns(Set<CompositeVulnerability> vulns) {
        Set<CompositeVulnerability> out = new HashSet<>();

        // if no vulnerabilities, return empty set
        if(vulns.isEmpty()) return out;

        Map<String, CompositeVulnerability> idToVuln = new HashMap<>();
        vulns.forEach(v -> idToVuln.put(v.getCveId(), v));

        // generate comma separated string of question marks for cve_id candidates
        String questionMarks = IntStream.range(0, vulns.size()).mapToObj(i -> "?").collect(Collectors.joining(","));
        String query = "SELECT nvdsourceurl.cve_id, nvdsourceurl.source_url, nvddata.published_date, nvddata.status\n" +
                "FROM nvdsourceurl\n" +
                "JOIN nvddata ON nvdsourceurl.cve_id = nvddata.cve_id\n" +
                "WHERE nvdsourceurl.cve_id IN (" + questionMarks + ")";
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(query)) {
            int i = 0;
            for (CompositeVulnerability v : vulns) {
                pstmt.setString(++i, v.getCveId());
            }
            ResultSet res = pstmt.executeQuery();
            String cveId = null;
            String lastCveId = null;
            Map<String, List<String>> sourceMap = new HashMap<>();
            boolean foundOne = false;
            while (res.next()) { // goes through each matching cve_id, creates the NvdVuln and attaches it to the CompVuln
                // Store last cve id to determine duplicate entries
                lastCveId = cveId;
                foundOne = true;

                // Update cveId value
                cveId = res.getString("cve_id");

                // Create object when source list has been compiled
                if(lastCveId != null && !lastCveId.equals(cveId)) {
                    NvdVulnerability nvdVuln = new NvdVulnerability(
                            cveId,
                            res.getTimestamp("published_date"),
                            res.getString("status"),
                            sourceMap.get(cveId)
                    );
                    CompositeVulnerability compVuln = idToVuln.get(cveId);
                    compVuln.setNvdVuln(nvdVuln);
                    out.add(compVuln);
                }

                // Create list or add to it as needed
                List<String> sources = sourceMap.get(cveId);
                if(sources == null) sources = new ArrayList<>();
                sources.add(res.getString("source_url"));
                sourceMap.put(cveId, sources);
            }

            // If only one result was found
            if(lastCveId == null && foundOne) {
                NvdVulnerability nvdVuln = new NvdVulnerability(
                        cveId,
                        res.getTimestamp("published_date"),
                        res.getString("status"),
                        sourceMap.get(cveId)
                );
                CompositeVulnerability compVuln = idToVuln.get(cveId);
                compVuln.setNvdVuln(nvdVuln);
                out.add(compVuln);
            }
        } catch (SQLException ex) {
            log.error("Error while inserting time gaps.\n{}", ex);
        }
        return out;
    }

    // todo lots of duplicate code for nvd/mitre, should find a suitable abstraction
    public Set<CompositeVulnerability> attachMitreVulns(Set<CompositeVulnerability> vulns) {
        Set<CompositeVulnerability> out = new HashSet<>();

        // if no vulnerabilities, return empty set
        if(vulns.isEmpty()) return out;

        Map<String, CompositeVulnerability> idToVuln = new HashMap<>();
        vulns.forEach(v -> idToVuln.put(v.getCveId(), v));

        // generate comma separated string of question marks for cve_id candidates
        String questionMarks = IntStream.range(0, vulns.size()).mapToObj(i -> "?").collect(Collectors.joining(","));
        String query = "SELECT cve_id, status FROM mitredata WHERE cve_id IN (" + questionMarks + ")";
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(query)) {
            int i = 0;
            for (CompositeVulnerability v : vulns) {
                pstmt.setString(++i, v.getCveId());
            }
            ResultSet res = pstmt.executeQuery();
            while (res.next()) {
                String cveId = res.getString("cve_id");
                MitreVulnerability mitreVuln = new MitreVulnerability(cveId, res.getString("status"));
                CompositeVulnerability compVuln = idToVuln.get(cveId);
                compVuln.setMitreVuln(mitreVuln);
                out.add(compVuln);
            }
        } catch (SQLException ex) {
            log.error("Error while inserting time gaps.\n{}", ex);
        }
        return out;
    }




    private final String getCveSourcesNVDSql = "SELECT cve_id, source_url FROM nvdsourceurl WHERE cve_id = ?;";
    /**
     * Method for getting the source url from nvddata
     *
     * @param cve_id CVE being processed
     * @return source url
     */
    public ArrayList<String> getCveSourcesNVD(String cve_id) {
        ArrayList<String> sourceURL = new ArrayList<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(getCveSourcesNVDSql)) {
            pstmt.setString(1, cve_id);
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                sourceURL.add(rs.getString("source_url"));
            }
        } catch (Exception e) {
            log.error("ERROR: Failed to get source URL for CVE ID {}\n{}", cve_id, e.getMessage());
        }
        return sourceURL;
    }
}
