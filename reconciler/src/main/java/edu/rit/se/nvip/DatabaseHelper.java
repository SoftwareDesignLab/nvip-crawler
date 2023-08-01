package edu.rit.se.nvip;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.pool.HikariPool;
import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.cwe.CWE;
import edu.rit.se.nvip.model.*;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.sql.*;
import java.util.*;

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
    private static final String INSERT_DESCRIPTION = "INSERT INTO description (description, created_date, gpt_func, cve_id) VALUES (?, ?, ?, ?)";
    private static final String DELETE_JOB = "DELETE FROM cvejobtrack WHERE cve_id = ?";
    private static final String UPDATE_CVSS = "UPDATE cvss SET base_score = ?, impact_score = ? WHERE cve_id = ?";
    private static final String INSERT_CVSS = "INSERT INTO cvss (base_score, impact_score, cve_id, create_date) VALUES (?, ?, ?, ?)";
    private static final String INSERT_VDO = "INSERT INTO vdocharacteristic (vdo_label, vdo_noun_group, vdo_confidence, cve_id, created_date) VALUES (?, ?, ?, ?, ?)";
    private static final String INSERT_CWE = "INSERT INTO weakness (cve_id, cwe_id) VALUES (?, ?)";
    private static final String DELETE_VDO = "DELETE FROM vdocharacteristic WHERE cve_id = ?";
    private static final String DELETE_CWE = "DELETE FROM weakness WHERE cve_id = ?";
    private static final String MITRE_COUNT = "SELECT COUNT(*) AS num_rows FROM mitredata;";
    private static final String MITRE_NVD_STATUS_INSERT = "INSERT INTO nvdmitrestatus (cve_id, create_date, in_nvd, in_mitre) VALUES (?, ?, ?, ?)";
    private static final String MITRE_NVD_STATUS_UPDATE = "UPDATE nvdmitrestatus SET in_nvd = ?, in_mitre = ? WHERE cve_id = ?";
    private static final String INSERT_MITREDATA = "INSERT INTO mitredata (cve_id, mitreStatus) VALUES (?, ?)";
    private static final String UPDATE_MITREDATA = "UPDATE mitredata SET mitreStatus = 1 WHERE cve_id = ?";
    private static final String UPDATE_MITRE_STATUS = "UPDATE nvdmitrestatus set in_mitre = 1 where cve_id = ?";
    private static final String UPDATE_NVD_STATUS = "UPDATE nvdmitrestatus set in_nvd = 1 where cve_id = ?";



    private static final String GET_ALL_NEW_CVES_NVD = "SELECT cve_id, published_date, status FROM nvddata order by cve_id desc";
    private static final String GET_ALL_NEW_CVES_MITRE = "SELECT cve_id, status FROM mitredata order by cve_id desc";
    private static final String GET_ALL_CVES = "SELECT cve_id FROM vulnerability order by cve_id desc";
    private static final String INSERT_NVDDATA = "INSERT INTO nvddata (cve_id, published_date, status) VALUES (?, ?, ?)";
    private static final String UPDATE_NVDDATA = "UPDATE nvddata SET in_nvd = 1 WHERE cve_id = ?";
    private static final String INSERT_NVD_MITRE_STATUS = "INSERT INTO nvdmitrestatus (cve_id, in_nvd, in_mitre, created_date) VALUES (?, ?, ?)";

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
            populateDescriptionInsert(descriptionStatement, vuln);
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
                populateJTInsert(jtStatement, vuln, rawVuln);
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

    private void populateDescriptionInsert(PreparedStatement descriptionStatement, CompositeVulnerability vuln) throws SQLException {
        descriptionStatement.setString(1, vuln.getDescription());
        descriptionStatement.setTimestamp(2, vuln.getDescriptionCreateDate());
        descriptionStatement.setString(3, vuln.getBuildString());
        descriptionStatement.setString(4, vuln.getCveId());
    }

    private void populateJTInsert(PreparedStatement jtStatement, CompositeVulnerability vuln, RawVulnerability rawVuln) throws SQLException {
        jtStatement.setInt(1, vuln.getDescriptionId());
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


    /**
     * for Getting NVD CVEs in nvddata
     * @return
     */
    public ArrayList<NvdVulnerability> getAllNvdCVEs() {

        ArrayList<NvdVulnerability> nvdVulnerabilities = new ArrayList<>();

        try (Connection connection = getConnection();
             PreparedStatement pstmt = connection.prepareStatement(GET_ALL_NEW_CVES_NVD)) {
            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {

                try {
                    nvdVulnerabilities.add(new NvdVulnerability(rs.getString("cve_id"), rs.getTimestamp("published_date"), rs.getString("status")));
                } catch (Exception ignore) {}

            }
        } catch (Exception e) {
            logger.error("ERROR: Failed to grab NVD CVEs from nvddata table\n{}", e.toString());
        }

        return nvdVulnerabilities;
    }
    public Set<MitreVulnerability> getAllMitreCVEs() {

        Set<MitreVulnerability> mitreVulns = new HashSet<>();

        try (Connection connection = getConnection();
             PreparedStatement pstmt = connection.prepareStatement(GET_ALL_NEW_CVES_MITRE)) {
            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {
                try {
                    mitreVulns.add(new MitreVulnerability(rs.getString("cve_id"), rs.getString("status")));
                } catch (Exception ignore) {}

            }
        } catch (Exception e) {
            logger.error("ERROR: Failed to grab NVD CVEs from nvddata table\n{}", e.toString());
        }

        return mitreVulns;
    }


    /**
     * for inserting a NVD Vulnerability in the nvddata table
     * @param nvdCve
     * @return
     */
    public int updateNvdData(NvdVulnerability nvdCve, boolean isUpdate) {

        try (Connection connection = getConnection();
             PreparedStatement pstmt = connection.prepareStatement(INSERT_NVDDATA);
             PreparedStatement updateStmt = connection.prepareStatement(UPDATE_NVDDATA)) {
            if(!isUpdate) {
                pstmt.setString(1, nvdCve.getCveId());
                pstmt.setTimestamp(2, nvdCve.getPublishDate());
                pstmt.setString(3, nvdCve.getStatus().toString());
                pstmt.execute();
            }else{
                updateStmt.setString(1, nvdCve.getCveId());
            }

            logger.info("Successfully Inserted CVE {} with Published Date {} and Status {} into nvd_data", nvdCve.getCveId(), nvdCve.getPublishDate(), nvdCve.getStatus());

            return 1;
        } catch (Exception e) {
            logger.error("ERROR: Failed to insert CVE {} with Published Date {} ans Status {} into nvd_data table", nvdCve.getCveId(), nvdCve.getPublishDate(), nvdCve.getStatus());
        }

        return 0;
    }

    public Set<NvdVulnerability> upsertNvdData(Set<NvdVulnerability> nvdCves) {
        List<NvdVulnerability> nvdVulnList = new ArrayList<>(nvdCves); // need order
        Set<NvdVulnerability> inserted = new HashSet<>(); // not updates
        String query = "INSERT INTO nvddata (cve_id, published_date, status) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE status = VALUES(status)";

        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            conn.setAutoCommit(false);
            for (NvdVulnerability vuln : nvdVulnList) {
                pstmt.setString(1, vuln.getCveId());
                pstmt.setTimestamp(2, vuln.getPublishDate());
                pstmt.setString(3, vuln.getStatus().toString());
                pstmt.addBatch();
            }
            int[] insertCounts = pstmt.executeBatch();
            conn.commit();
            for (int i = 0; i < nvdVulnList.size(); i++) {
                int count = insertCounts[i];
                // count == 1 -> successful insert
                // count == 2 -> successful update
                // other -> something went wrong, but i don't think that's possible since this is atomic
                if (count == 1) { // 1 row affected means successful insert
                    inserted.add(nvdVulnList.get(i));
                }
            }
        } catch (SQLException ex) {
            logger.error("Error while updating nvddata table");
            logger.error(ex);
        }
        return inserted;
    }

    /**
     * updates (or inserts) CVSS score of given vuln
     *
     * @param vuln
     * @return
     */
    public int updateCVSS(CompositeVulnerability vuln) {
        if (vuln.getCvssScoreInfo() == null) {
            logger.warn("CVE {} does not have a CVSS score - skipping its cvss insertion", vuln.getCveId());
            return 0;
        }
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
             PreparedStatement upsertStatement = conn.prepareStatement(isUpdate ? UPDATE_CVSS: INSERT_CVSS)) {

            if (isUpdate) {
                populateCVSSUpdate(upsertStatement, vuln.getCvssScoreInfo());
            } else {
                populateCVSSInsert(upsertStatement, vuln.getCvssScoreInfo());
            }

            upsertStatement.execute();

            return 1;

        } catch (SQLException e) {
            logger.error("ERROR: Failed to update CVSS, {}", e.getMessage());
        }
        return 0;
    }
    /**
     * updates (or inserts) vdo info of given vuln
     *
     * @param vuln
     * @return
     */
    public int updateVDO(CompositeVulnerability vuln) {
        try (Connection conn = getConnection();
             PreparedStatement insertStatement = conn.prepareStatement(INSERT_VDO);
             PreparedStatement deleteStatement = conn.prepareStatement(DELETE_VDO)) {
            conn.setAutoCommit(false);
            deleteStatement.setString(1, vuln.getCveId());
            deleteStatement.execute();
            for (VdoCharacteristic vdo : vuln.getVdoCharacteristic()) {
                populateVDOInsert(insertStatement, vdo);
                insertStatement.addBatch();
            }
            insertStatement.executeBatch();
            conn.commit();
            return 1;
        } catch (SQLException e) {
            logger.error("ERROR: Failed to update VDO, {}", e.getMessage());
        }
        return 0;
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

    private void populateCVSSUpdate(PreparedStatement pstmt, CvssScore cvss) throws SQLException {
        pstmt.setDouble(1, cvss.getSeverityId());
        pstmt.setString(2, cvss.getImpactScore());
        pstmt.setString(3, cvss.getCveId());
    }
    private void populateCVSSInsert(PreparedStatement pstmt, CvssScore cvss) throws SQLException {
        pstmt.setDouble(1, cvss.getSeverityId());
        pstmt.setString(2, cvss.getImpactScore());
        pstmt.setString(3, cvss.getCveId());
        pstmt.setTimestamp(4, new Timestamp(System.currentTimeMillis()));

    }

    private void populateVDOInsert(PreparedStatement pstmt, VdoCharacteristic vdo) throws SQLException {
        pstmt.setString(1, String.valueOf(CveCharacterizer.VDOLabel.getVdoLabel(vdo.getVdoLabelId())));
        pstmt.setString(2, String.valueOf(CveCharacterizer.VDONounGroup.getVdoNounGroup(vdo.getVdoNounGroupId())));
        pstmt.setDouble(3, vdo.getVdoConfidence());
        pstmt.setString(4, vdo.getCveId());
        pstmt.setTimestamp(5, new Timestamp(System.currentTimeMillis()));

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
    public int insertMitreData(Set<MitreVulnerability> vulns){

        try (Connection conn = getConnection();
             PreparedStatement insertStatement = conn.prepareStatement(INSERT_MITREDATA)) {

            for(MitreVulnerability vuln : vulns){
                insertStatement.setString(1, vuln.getCveId());
                insertStatement.setInt(2, vuln.getStatus().getStatusInt());
                insertStatement.addBatch();

            }
            insertStatement.executeBatch();
            return 1;
        } catch (SQLException e) {
            logger.error("ERROR: Failed to update mitredata table, {}", e.getMessage());
            return 0;
        }
    }
    public int updateMitreData(Set<MitreVulnerability> vulns){

        try (Connection conn = getConnection();
             PreparedStatement insertStatement = conn.prepareStatement(UPDATE_MITREDATA)) {

            for(MitreVulnerability vuln : vulns){
                insertStatement.setString(1, vuln.getCveId());
                insertStatement.addBatch();

            }
            insertStatement.executeBatch();
            return 1;
        } catch (SQLException e) {
            logger.error("ERROR: Failed to update mitredata table, {}", e.getMessage());
            return 0;
        }
    }

    public int setInNvdMitreStatus(Set<Vulnerability> newVulns) {
        try (Connection conn = getConnection();
             PreparedStatement pstmtMitre = conn.prepareStatement(UPDATE_MITRE_STATUS);
             PreparedStatement pstmtNvd = conn.prepareStatement(UPDATE_NVD_STATUS)) {
            for(Vulnerability vuln : newVulns){
                if (vuln instanceof MitreVulnerability) {
                    pstmtMitre.setString(1, vuln.getCveId());
                    pstmtMitre.addBatch();
                }else if (vuln instanceof NvdVulnerability){
                    pstmtNvd.setString(1, vuln.getCveId());
                    pstmtNvd.addBatch();
                }else{
                    throw new SQLException();
                }
            }
            pstmtMitre.executeBatch();
            pstmtNvd.executeBatch();
            return 1;
        }
        catch (SQLException e) {
            logger.error("ERROR: Failed to update mitre status in nvdmitrestatus table, {}", e.getMessage());
            return 0;
        }
    }

    public int insertNvdMitreStatuses(Set<CompositeVulnerability> reconciledVulns) {
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(INSERT_NVD_MITRE_STATUS)) {
            for (CompositeVulnerability vuln : reconciledVulns) {
                pstmt.setString(1, vuln.getCveId());
                pstmt.setInt(2, vuln.isInNvd() ? 1 : 0);
                pstmt.setInt(3, vuln.isInMitre() ? 1 : 0);
                pstmt.setTimestamp(4, new Timestamp(System.currentTimeMillis())); // todo not sure if we really need this (create_date), ask chris if we can drop
                pstmt.addBatch();
            }
            pstmt.executeBatch();
            return 1;
        } catch (SQLException ex) {
            logger.error("Error while inserting rows into nvdmitrestatus table\n{}", ex.toString());
            ex.printStackTrace();
            return 0;
        }
    }
}
