package edu.rit.se.nvip;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.pool.HikariPool;
import edu.rit.se.nvip.cwe.CWE;
import edu.rit.se.nvip.model.*;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.sql.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class DatabaseHelper {

    private HikariConfig config = null;
    private HikariDataSource dataSource;
    private static final Logger logger = LogManager.getLogger(DatabaseHelper.class.getSimpleName());
    private static final String databaseType = "mysql";
    private static DatabaseHelper databaseHelper = null;

    private static final String GET_JOBS = "SELECT * FROM cvejobtrack";
    private static final String GET_RAW_BY_CVE_ID = "SELECT * FROM rawdescription WHERE cve_id = ?";
    private static final String UPDATE_FILTER_STATUS = "UPDATE rawdescription SET is_garbage = ? WHERE raw_description_id = ?";
    private static final String GET_VULN = "SELECT v.*, d.description_id, d.description, d.created_date AS description_date, d.gpt_func " +
            "FROM vulnerability AS v INNER JOIN description AS d ON v.description_id = d.description_id WHERE v.cve_id = ?";
    private static final String GET_USED_RAW_VULNS = "SELECT rd.* " +
            "FROM vulnerability as v " +
            "INNER JOIN description AS d ON v.description_id = d.description_id " +
            "INNER JOIN rawdescriptionjt AS rdjt ON d.description_id = rdjt.description_id " +
            "INNER JOIN rawdescription AS rd ON rdjt.raw_description_id = rd.raw_description_id " +
            "WHERE v.cve_id = ?";


    private static final String INSERT_VULNERABILITY = "INSERT INTO vulnerability (cve_id, description_id, created_date, published_date, last_modified_date) VALUES (?, ?, ?, ?, ?)";
    private static final String UPDATE_VULNERABILITY = "UPDATE vulnerability SET description_id = ?, published_date = ?, last_modified_date = ? WHERE cve_id = ?";
    private static final String INSERT_JT = "INSERT INTO rawdescriptionjt (description_id, raw_description_id) VALUES (?, ?)";
    private static final String INSERT_DESCRIPTION = "INSERT INTO description (description, created_date, gpt_func, cve_id, is_user_generated) VALUES (?, ?, ?, ?, ?)";
    private static final String DELETE_JOB = "DELETE FROM cvejobtrack WHERE cve_id = ?";
    private static final String INSERT_CVSS = "INSERT INTO cvss (cve_id, create_date, base_score, impact_score) VALUES (?, NOW(), ?, ?)";
    private static final String INSERT_VDO = "INSERT INTO vdocharacteristic (cve_id, created_date, vdo_label, vdo_noun_group, vdo_confidence, is_active) VALUES (?, NOW(), ?, ?, ?, 1)";
    private static final String UPDATE_VDO_ACTIVE = "UPDATE vdocharacteristic SET is_active=0 WHERE user_id IS NULL";
    private static final String INSERT_CWE = "INSERT INTO weakness (cve_id, cwe_id) VALUES (?, ?)";
    private static final String DELETE_CWE = "DELETE FROM weakness WHERE cve_id = ?";
    private static final String MITRE_COUNT = "SELECT COUNT(*) AS num_rows FROM mitredata;";
    private static final String BACKFILL_NVD_TIMEGAPS = "INSERT INTO timegap (cve_id, location, timegap, created_date) " +
            "SELECT v.cve_id, 'nvd', TIMESTAMPDIFF(HOUR, v.created_date, n.published_date), NOW() " +
            "FROM nvddata AS n INNER JOIN vulnerability AS v ON n.cve_id = v.cve_id WHERE v.cve_id = ? " +
            "ON DUPLICATE KEY UPDATE cve_id = v.cve_id";
    private static final String BACKFILL_MITRE_TIMEGAPS = "INSERT INTO timegap (cve_id, location, timegap, created_date) " +
            "SELECT v.cve_id, 'mitre', TIMESTAMPDIFF(HOUR, v.created_date, NOW()), NOW() " +
            "FROM mitredata AS m INNER JOIN vulnerability AS v ON m.cve_id = v.cve_id WHERE v.cve_id = ?  " +
            "ON DUPLICATE KEY UPDATE cve_id = v.cve_id";
    private static final String UPSERT_NVD = "INSERT INTO nvddata (cve_id, published_date, status, last_modified) VALUES (?, ?, ?, NOW()) AS input " +
            "ON DUPLICATE KEY UPDATE " +
            "status = input.status, " +
            "last_modified = IF(input.status <> nvddata.status, NOW(), nvddata.last_modified)";
    private static final String INSERT_NVD_SOURCE_URLS = "INSERT INTO nvdsourceurl (cve_id, source_url) VALUES (?, ?) as input" +
            "ON DUPLICATE KEY UPDATE " +
            "cve_id = input.cve_id";
    private static final String UPSERT_MITRE = "INSERT INTO mitredata (cve_id, status, last_modified) VALUES (?, ?, NOW()) AS input " +
            "ON DUPLICATE KEY UPDATE " +
            "status = input.status, " +
            "last_modified = IF(input.status <> mitredata.status, NOW(), mitredata.last_modified)";
    private static final String SELECT_NVD_BY_DATE = "SELECT cve_id FROM nvddata WHERE last_modified >= DATE_SUB(NOW(), INTERVAL 2 MINUTE)";
    private static final String SELECT_MITRE_BY_DATE = "SELECT cve_id FROM mitredata WHERE last_modified >= DATE_SUB(NOW(), INTERVAL 2 MINUTE)";
    private static final String INSERT_RUN_STATS = "INSERT INTO runhistory (run_date_time, total_cve_count, new_cve_count, updated_cve_count, not_in_nvd_count, not_in_mitre_count, not_in_both_count, avg_time_gap_nvd, avg_time_gap_mitre)" +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

    public static synchronized DatabaseHelper getInstance() {
        if (databaseHelper == null) {
            HikariConfig config = createHikariConfigFromEnvironment();
            databaseHelper = new DatabaseHelper(config);
        }
        return databaseHelper;
    }

    public static synchronized DatabaseHelper getInstance(String url, String username, String password) {
        if (databaseHelper == null) {
            HikariConfig config = createHikariConfigFromArgs(url, username, password);
            databaseHelper = new DatabaseHelper(config);
        }
        return databaseHelper;
    }

    protected DatabaseHelper(HikariConfig config) {
        try {
            logger.info("New NVIP.DatabaseHelper instantiated! It is configured to use " + databaseType + " database!");
            Class.forName("com.mysql.cj.jdbc.Driver");

        } catch (ClassNotFoundException e2) {
            logger.error("Error while loading database type");
            logger.error(e2);
        }

        try {
            dataSource = new HikariDataSource(config); // init data source
        } catch (HikariPool.PoolInitializationException e2) {
            logger.error("Error initializing data source! Check the value of the database user/password in the env.list file!");
            System.exit(1);

        }
    }

    protected static HikariConfig createHikariConfigFromArgs(String url, String username, String password) {
        HikariConfig hikariConfig = new HikariConfig();
        hikariConfig.setJdbcUrl(url);
        hikariConfig.setUsername(username);
        hikariConfig.setPassword(password);
        return hikariConfig;
    }

    protected static HikariConfig createHikariConfigFromEnvironment() {
        String url = ReconcilerEnvVars.getHikariURL();
        HikariConfig hikariConfig;

        if (url != null) {
            logger.info("Creating HikariConfig with url={}", url);
            hikariConfig = new HikariConfig();
            hikariConfig.setJdbcUrl(url);
            hikariConfig.setUsername(ReconcilerEnvVars.getHikariUser());
            hikariConfig.setPassword(ReconcilerEnvVars.getHikariPassword());

            System.getenv().entrySet().stream()
                    .filter(e -> e.getKey().startsWith("HIKARI_"))
                    .peek(e -> logger.info("Setting {} to HikariConfig", e.getKey()))
                    .forEach(e -> hikariConfig.addDataSourceProperty(e.getKey(), e.getValue()));

        } else {
            hikariConfig = null;
        }

        return hikariConfig;
    }

    /**
     * Retrieves the connection from the DataSource (HikariCP)
     *
     * @return the connection pooling connection
     * @throws SQLException
     */
    public Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    /**
     * Tests the database connection
     * @return
     */
    public boolean testDbConnection() {
        try {
            Connection conn = dataSource.getConnection();
            if (conn != null) {
                conn.close();
                return true;
            } else
                return false;
        } catch (SQLException e) {
            logger.error(e.toString());
        }
        return false;
    }

    /**
     * Gets jobs
     * @return
     */
    public Set<String> getJobs() {
        Set<String> cveIds = new HashSet<>();
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(GET_JOBS)) {
            ResultSet res = pstmt.executeQuery();
            while (res.next()) {
                cveIds.add(res.getString("cve_id"));
            }
        } catch (SQLException ex) {
            logger.error("Error retrieving jobs");
            logger.error(ex);
            return new HashSet<>();
        }
        return cveIds;
    }

    /**
     * Gets a set of Raw Vulnerabilities
     * @param cveId
     * @return
     */
    public Set<RawVulnerability> getRawVulnerabilities(String cveId) {
        Set<RawVulnerability> rawVulns = new HashSet<>();
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(GET_RAW_BY_CVE_ID)) {
            pstmt.setString(1, cveId);
            ResultSet res = pstmt.executeQuery();
            while (res.next()) {
                RawVulnerability rawVuln = rawVulnFromRes(res);
                rawVulns.add(rawVuln);
            }
        } catch (SQLException ex) {
            logger.error("Error retrieving rawdescriptions");
            logger.error(ex);
            return new HashSet<>();
        }
        return rawVulns;
    }

    /**
     *
     * @param rejectedRawVulns
     */
    public void updateFilterStatus(Set<RawVulnerability> rejectedRawVulns) {
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(UPDATE_FILTER_STATUS)) {
            for (RawVulnerability vuln : rejectedRawVulns) {
                pstmt.setInt(1, vuln.getFilterStatus().value);
                pstmt.setInt(2, vuln.getId());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        } catch (SQLException ex) {
            logger.error("Error marking rawdescriptions as garbage");
            logger.error(ex);
        }
    }

    public CompositeVulnerability getCompositeVulnerability(String cveId) {
        Set<RawVulnerability> usedRawVulns = getUsedRawVulnerabilities(cveId);
        return getSummaryVulnerability(cveId, usedRawVulns);
    }

    // very hacky to use the rawVulns as an arg, there's a better way to handle this join
    private CompositeVulnerability getSummaryVulnerability(String cveId, Set<RawVulnerability> rawVulns) {
        CompositeVulnerability vuln = null;
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(GET_VULN)) {
            pstmt.setString(1, cveId);
            ResultSet res = pstmt.executeQuery();
            if (res.next()) {
                CompositeDescription compDes = new CompositeDescription(
                        res.getInt("description_id"),
                        res.getString("cve_id"),
                        res.getString("description"),
                        res.getTimestamp("created_date"),
                        res.getString("gpt_func"),
                        rawVulns
                );
                vuln = new CompositeVulnerability(
                        cveId,
                        res.getInt("vuln_id"),
                        compDes,
                        res.getTimestamp("published_date"),
                        res.getTimestamp("last_modified_date"),
                        res.getTimestamp("created_date")
                );
            }
        } catch (SQLException ex) {
            logger.error("Error retrieving vulnerability " + cveId);
            logger.error(ex);
            return null;
        }
        return vuln;
    }

    public Set<RawVulnerability> getUsedRawVulnerabilities(String cveId) {
        Set<RawVulnerability> rawVulns = new HashSet<>();
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(GET_USED_RAW_VULNS)) {
            pstmt.setString(1, cveId);
            ResultSet res = pstmt.executeQuery();
            while (res.next()) {
                RawVulnerability rawVuln = rawVulnFromRes(res);
                rawVulns.add(rawVuln);
            }
        } catch (SQLException ex) {
            logger.error("Error retrieving used rawdescriptions with cve_id " + cveId);
            logger.error(ex);
            return new HashSet<>();
        }
        return rawVulns;
    }

    /**
     * Inserts, updates, or does nothing for a composite vulnerability based on its reconciliation status
     * @param vuln composite vulnerability
     * @return 1 if inserted/updated, 0 if skipped, -1 if error
     */
    public int insertOrUpdateVulnerabilityFull(CompositeVulnerability vuln) {
        boolean isUpdate;
        switch (vuln.getReconciliationStatus()) {
            case UPDATED:
                isUpdate = true;
                break;
            case NEW:
                isUpdate = false;
                break;
            default:
                return 0;
        }


        try (Connection conn = getConnection();
             PreparedStatement descriptionStatement = conn.prepareStatement(INSERT_DESCRIPTION, Statement.RETURN_GENERATED_KEYS);
             PreparedStatement jtStatement = conn.prepareStatement(INSERT_JT);
             PreparedStatement vulnStatement = conn.prepareStatement(isUpdate ? UPDATE_VULNERABILITY : INSERT_VULNERABILITY);
             PreparedStatement jobStatement = conn.prepareStatement(DELETE_JOB)) {
            // handle all these atomically
            conn.setAutoCommit(false);
            // insert into description table
            populateDescriptionInsert(descriptionStatement, vuln.getSystemDescription());
            descriptionStatement.executeUpdate();
            // get generated description id
            ResultSet rs = descriptionStatement.getGeneratedKeys();
            if (rs.next()) {
                vuln.setDescriptionId(rs.getInt(1));
            } else {
                // Pretty sure an exception would have been thrown by now anyway, but just in case...
                logger.error("ERROR: Failure in inserting to the description table");
                throw new SQLException();
            }
            // batch insert into joint table
            for (RawVulnerability rawVuln : vuln.getComponents()) {
                populateJTInsert(jtStatement, vuln.getSystemDescription(), rawVuln);
                jtStatement.addBatch();
            }
            jtStatement.executeBatch();
            // insert/update into vulnerability table
            if (isUpdate) {
                populateVulnUpdate(vulnStatement, vuln);
            } else {
                populateVulnInsert(vulnStatement, vuln);
            }
            vulnStatement.executeUpdate();
            // remove job
            populateJobDelete(jobStatement, vuln);
            jobStatement.executeUpdate();
            // execute atomically
            conn.commit();
        } catch (SQLException ex) {
            logger.error("ERROR while {} {}", isUpdate ? "updating" : "inserting", vuln.getCveId());
            logger.error(ex);
            return -1;
        }
        return 1;
    }

    public void insertDescription(CompositeDescription compDesc) {
        try (Connection conn = getConnection();
             PreparedStatement descriptionStatement = conn.prepareStatement(INSERT_DESCRIPTION);
             PreparedStatement jtStatement = conn.prepareStatement(INSERT_JT)) {
            conn.setAutoCommit(false);
            populateDescriptionInsert(descriptionStatement, compDesc);
            descriptionStatement.executeUpdate();
            ResultSet rs = descriptionStatement.getGeneratedKeys();
            if (rs.next()) {
                compDesc.setId(rs.getInt(1));
            } else {
                // Pretty sure an exception would have been thrown by now anyway, but just in case...
                logger.error("ERROR: Failure in inserting a description for {}", compDesc.getCveId());
                throw new SQLException();
            }
            for (RawVulnerability rawVuln : compDesc.getSources()) {
                populateJTInsert(jtStatement, compDesc, rawVuln);
                jtStatement.addBatch();
            }
            jtStatement.executeBatch();
            conn.commit();
        } catch (SQLException ex) {
            logger.error("Error while inserting description for {}", compDesc.getCveId());
        }
    }

    private void populateDescriptionInsert(PreparedStatement descriptionStatement, CompositeDescription compDesc) throws SQLException {
        descriptionStatement.setString(1, compDesc.getDescription());
        descriptionStatement.setTimestamp(2, compDesc.getCreatedDate());
        descriptionStatement.setString(3, compDesc.getBuildString());
        descriptionStatement.setString(4, compDesc.getCveId());
        descriptionStatement.setInt(5, compDesc.isUserGenerated() ? 1 : 0);
    }

    private void populateJTInsert(PreparedStatement jtStatement, CompositeDescription compDesc, RawVulnerability rawVuln) throws SQLException {
        jtStatement.setInt(1, compDesc.getId());
        jtStatement.setInt(2, rawVuln.getId());
    }

    private void populateVulnInsert(PreparedStatement vulnStatement, CompositeVulnerability vuln) throws SQLException {
        vulnStatement.setString(1, vuln.getCveId());
        vulnStatement.setInt(2, vuln.getDescriptionId());
        vulnStatement.setTimestamp(3, vuln.getCreateDate());
        vulnStatement.setTimestamp(4, vuln.getPublishDate());
        vulnStatement.setTimestamp(5, vuln.getLastModifiedDate());
    }

    private void populateVulnUpdate(PreparedStatement vulnStatement, CompositeVulnerability vuln) throws SQLException {
        vulnStatement.setInt(1, vuln.getDescriptionId());
        vulnStatement.setTimestamp(2, vuln.getPublishDate());
        vulnStatement.setTimestamp(3, vuln.getLastModifiedDate());
        vulnStatement.setString(4, vuln.getCveId());
    }

    private void populateJobDelete(PreparedStatement jobStatement, CompositeVulnerability vuln) throws SQLException {
        jobStatement.setString(1, vuln.getCveId());
    }

    private RawVulnerability rawVulnFromRes(ResultSet res) {
        RawVulnerability rawVuln = null;
        try {
            rawVuln = new RawVulnerability(
                    res.getInt("raw_description_id"),
                    res.getString("cve_id"),
                    res.getString("raw_description"),
                    res.getTimestamp("published_date"),
                    res.getTimestamp("last_modified_date"),
                    res.getTimestamp("published_date"),
                    res.getString("source_url"),
                    res.getString("source_type"),
                    res.getInt("is_garbage") // todo change this column to "filter_status" to reflect its new purpose
            );
        } catch (SQLException ex) {
            logger.error(ex);
        }
        return rawVuln;
    }

    public Set<NvdVulnerability> upsertNvdData(Set<NvdVulnerability> nvdCves) {
        List<NvdVulnerability> nvdVulnList = new ArrayList<>(nvdCves); // need order
        Set<NvdVulnerability> toBackfill = new HashSet<>(); // inserts and nontrivial updates

        Map<String, NvdVulnerability> idToVuln = new HashMap<>();
        nvdCves.forEach(v->idToVuln.put(v.getCveId(), v));

        try (Connection conn = getConnection();
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
            insertSourceUrlsStmt.executeBatch();
            upsertStmt.executeBatch();
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
            logger.error("Error while updating nvddata table");
            logger.error(ex);
        }
        return toBackfill;
    }

    public Set<MitreVulnerability> upsertMitreData(Set<MitreVulnerability> mitreCves) {
        List<MitreVulnerability> mitreVulnList = new ArrayList<>(mitreCves); // need order
        Set<MitreVulnerability> toBackfill = new HashSet<>(); // inserts and nontrivial updates

        Map<String, MitreVulnerability> idToVuln = new HashMap<>();
        mitreCves.forEach(v->idToVuln.put(v.getCveId(), v));

        try (Connection conn = getConnection();
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
            logger.error("Error while updating mitredata table");
            logger.error(ex);
        }
        return toBackfill;
    }

    public void insertCvssBatch(Set<CompositeVulnerability> vulns) {
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(INSERT_CVSS)) {
            for (CompositeVulnerability vuln : vulns) {
                if (!vuln.isRecharacterized() || vuln.getCvssScoreInfo() == null) {
                    continue;
                }
                populateCVSSInsert(pstmt, vuln.getCvssScoreInfo());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        } catch (SQLException e) {
            logger.error("Error while inserting cvss scores");
            logger.error(e);
        }
    }

    public void insertVdoBatch(Set<CompositeVulnerability> vulns) {
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(INSERT_VDO);
             PreparedStatement activeStmt = conn.prepareStatement(UPDATE_VDO_ACTIVE)) {
            conn.setAutoCommit(false);
            activeStmt.executeUpdate(); // set is_active to 0 for all the old system-generated vdo rows, leave user rows alone and let the API review endpoint handle those
            for (CompositeVulnerability vuln : vulns) {
                if (!vuln.isRecharacterized() || vuln.getVdoCharacteristics() == null) {
                    continue;
                }
                for (VdoCharacteristic vdo : vuln.getVdoCharacteristics()) {
                    populateVDOInsert(pstmt, vdo);
                    pstmt.addBatch();
                }
            }
            pstmt.executeBatch();
            conn.commit();
        } catch (SQLException ex) {
            logger.error("Error while inserting vdo labels");
            logger.error(ex);
        }
    }

    public int insertRun(RunStats run) {
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(INSERT_RUN_STATS)) {
            populateDailyRunInsert(pstmt, run);
            pstmt.execute();
            return 1;
        } catch (SQLException e) {
            logger.error("Failed to insert the the run statistics\n{}", e.toString());
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

    private void populateCVSSInsert(PreparedStatement pstmt, CvssScore cvss) throws SQLException {
        pstmt.setString(1, cvss.getCveId());
        pstmt.setDouble(2, cvss.getImpactScore());
        pstmt.setDouble(3, cvss.getSeverityClass().cvssSeverityId); // yes, id not string
    }

    private void populateVDOInsert(PreparedStatement pstmt, VdoCharacteristic vdo) throws SQLException {
        pstmt.setString(1, vdo.getCveId());
        pstmt.setString(2, vdo.getVdoLabel().vdoLabelForUI); // yes, they expect the string not the id
        pstmt.setString(3, vdo.getVdoNounGroup().vdoNameForUI); // yes, string not id
        pstmt.setDouble(4, vdo.getVdoConfidence());
    }

    public int insertCWEs(CompositeVulnerability vuln) {
        try (Connection conn = getConnection();
             PreparedStatement upsertStatement = conn.prepareStatement(INSERT_CWE);
             PreparedStatement deleteStatement = conn.prepareStatement(DELETE_CWE)) {
            conn.setAutoCommit(false);
            deleteStatement.setString(1, vuln.getCveId());
            deleteStatement.execute();
            for (CWE cwe : vuln.getCWEs()) {
                populateCWEInsert(upsertStatement, cwe, vuln.getCveId());
                upsertStatement.addBatch();
            }
            upsertStatement.executeBatch();
            conn.commit();
            return 1;
        } catch (SQLException e) {
            logger.error("ERROR: Failed to insert CWE, {}", e.getMessage());
        }
        return 0;
    }
    private void populateCWEInsert(PreparedStatement pstmt, CWE cwe, String cve_id) throws SQLException {
        pstmt.setString(1, cve_id);
        pstmt.setInt(2, cwe.getId());

    }

    public boolean isMitreTableEmpty() {
        try (Connection conn = getConnection();
             PreparedStatement upsertStatement = conn.prepareStatement(MITRE_COUNT);
             ResultSet resultSet = upsertStatement.executeQuery()) {

            if (resultSet.next()) {
                int rowCount = resultSet.getInt("num_rows");
                return rowCount == 0;
            } else {
                // This means no rows were returned by the query (something unexpected happened).
                logger.error("ERROR: No result returned from the query.");
                return false;
            }
        } catch (SQLException e) {
            logger.error("ERROR: Failed to get the amount of rows for mitredata table, {}", e.getMessage());
            return false;
        }
    }

    public void backfillNvdTimegaps(Set<NvdVulnerability> newNvdVulns) {
        // we don't need to compute time gaps ourselves
        // at this point these nvd vulns should already be in the nvddata table and we have create dates for all vulns in our system
        // so we can compute the timestamp difference within sql, and the inner join ensures this only happens for vulns we already have
        // the (cve_id, location) pair is a key in this table, so the last clause stops any duplicate time gaps
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(BACKFILL_NVD_TIMEGAPS)) {
            for (NvdVulnerability vuln : newNvdVulns) {
                pstmt.setString(1, vuln.getCveId());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        } catch (SQLException ex) {
            logger.error("Error while inserting time gaps");
            logger.error(ex);
        }
    }

    public void backfillMitreTimegaps(Set<MitreVulnerability> newNvdVulns) {
        // mitre vulns don't have publish dates - so we're using NOW as their "publish date" to compute time gaps until further notice
        // the (cve_id, location) pair is a key in this table, so the last clause stops any duplicate time gaps
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(BACKFILL_MITRE_TIMEGAPS)) {
            for (MitreVulnerability vuln : newNvdVulns) {
                pstmt.setString(1, vuln.getCveId());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        } catch (SQLException ex) {
            logger.error("Error while inserting time gaps");
            logger.error(ex);
        }
    }

    public void insertTimeGapsForNewVulns(Set<CompositeVulnerability> vulns) {
        String query = "INSERT INTO timegap (cve_id, location, timegap, created_date) VALUES (?, ?, ?, NOW())";
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(query)) {
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
        } catch (SQLException ex) {
            logger.error("Error while inserting time gaps for newly discovered vulnerabilities");
            logger.error(ex);
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
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(query)) {
            int i = 0;
            for (CompositeVulnerability v : vulns) {
                pstmt.setString(++i, v.getCveId());
            }
            ResultSet res = pstmt.executeQuery();
            boolean createObjects = false;
            String cveId = null;
            Map<String, List<String>> sourceMap = new HashMap<>();
            while (res.next()) { // goes through each matching cve_id, creates the NvdVuln and attaches it to the CompVuln
                // Check if cveId changed (ensures no duplicate objects created)
                if(cveId != null && !cveId.equals(res.getString("cve_id"))) createObjects = true;

                // Create objects
                if(createObjects) {
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

                // Update cveId value
                cveId = res.getString("cve_id");

                // Create list or add to it as needed
                List<String> sources = sourceMap.get(cveId);
                if(sources == null) sources = new ArrayList<>();
                sources.add(res.getString("source_url"));
                sourceMap.put(cveId, sources);
            }
        } catch (SQLException ex) {
            logger.error("Error while inserting time gaps");
            logger.error(ex);
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
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(query)) {
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
            logger.error("Error while inserting time gaps");
            logger.error(ex);
        }
        return out;
    }

}
