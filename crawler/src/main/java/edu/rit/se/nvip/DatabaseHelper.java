/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.pool.HikariPool.PoolInitializationException;
import edu.rit.se.nvip.model.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.sql.*;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 
 * The DatabaseHelper class is used to insert and update vulnerabilities found
 * from the webcrawler/processor to a sqlite database
 */
public class DatabaseHelper {
	protected NumberFormat formatter = new DecimalFormat("#0.00000");
	private HikariConfig config = null;
	private HikariDataSource dataSource;
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	String databaseType = "mysql";

	public final DateFormat longDateFormatMySQL = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	/**
	 * SQL sentences. Please include the INSERT/UPDATE/DELETE SQL sentences of each
	 * entity in this section!
	 */
	private final String insertVulnSql = "INSERT INTO vulnerability (cve_id, description, platform, introduced_date, published_date, created_date, last_modified_date, "
			+ "fixed_date, exists_at_nvd, exists_at_mitre, time_gap_nvd, time_gap_mitre) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);";
	private final String updateVulnSql = "UPDATE vulnerability SET description = ?," + "platform = ?,"
			+ "introduced_date = ?," + "published_date = ?," + "last_modified_date = ?,"
			+ "fixed_date = ? WHERE (cve_id = ?);";

	private final String updateNvdTimeGapSql = "UPDATE vulnerability SET time_gap_nvd = ? WHERE cve_id = ?;";
	private final String updateNvdStatusSql = "UPDATE vulnerability SET exists_at_nvd = ? WHERE cve_id = ?;";
	private final String updateMitreTimeGapSql = "UPDATE vulnerability SET time_gap_mitre = ? WHERE cve_id = ?;";
	private final String updateMitreStatusSql = "UPDATE vulnerability SET exists_at_mitre = ? WHERE cve_id = ?;";
	private final String insertCveStatusSql = "INSERT INTO cvestatuschange (vuln_id, cve_id, cpmpared_against, old_status_code, new_status_code, cve_description, time_gap_recorded, time_gap_hours, status_date, cve_create_date) VALUES (?,?,?,?,?,?,?,?,?,?);";

	private final String insertVulnSourceSql = "INSERT INTO vulnsourceurl (cve_id, url) VALUES (?,?);";
	private final String deleteVulnSourceSql = "DELETE FROM vulnsourceurl WHERE cve_id=?;";

	private final String selectAllNvipSourceSql = "SELECT * FROM nvipsourceurl;";

	private final String insertDailyRunSql = "INSERT INTO dailyrunhistory (run_date_time, crawl_time_min, total_cve_count, not_in_nvd_count, not_in_mitre_count,"
			+ "not_in_both_count, new_cve_count, avg_time_gap_nvd, avg_time_gap_mitre, added_cve_count, updated_cve_count) VALUES (?,?,?,?,?,?,?,?,?,?,?);";
	private final String updateDailyRunSql = "UPDATE dailyrunhistory SET crawl_time_min = ?, db_time_min = ?, total_cve_count = ?, not_in_nvd_count = ?, "
			+ "not_in_mitre_count = ?, not_in_both_count = ?, new_cve_count = ?, avg_time_gap_nvd = ?, avg_time_gap_mitre = ? WHERE (run_id = ?);";
	private final String selectAverageTimeGapNvd = "SELECT avg(v.time_gap_nvd) as gapNvd from vulnerability v where Date(v.created_date) >= CURDATE()";
	private final String selectAverageTimeGapMitre = "SELECT avg(v.time_gap_mitre) as gapMitre from vulnerability v where Date(v.created_date) >= CURDATE()";

	private final String insertVdoCharacteristicSql = "INSERT INTO vdocharacteristic (cve_id, vdo_label_id,vdo_confidence,vdo_noun_group_id) VALUES (?,?,?,?);";
	private final String deleteVdoCharacteristicSql = "DELETE FROM vdocharacteristic WHERE cve_id=?;";

	private final String insertCvssScoreSql = "INSERT INTO cvssscore (cve_id, cvss_severity_id, severity_confidence, impact_score, impact_confidence) VALUES (?,?,?,?,?);";
	private final String deleteCvssScoreSql = "DELETE FROM cvssscore WHERE cve_id=?;";

	private final String insertVulnerabilityUpdateSql = "INSERT INTO vulnerabilityupdate (vuln_id, column_name, column_value, run_id) VALUES (?,?,?,?);";
	private final String selectVulnerabilityIdSql = "SELECT vuln_id FROM vulnerability WHERE cve_id = ?";
	private final String selectCVEIdSql = "SELECT cve_id FROM vulnerability WHERE vuln_id = ?";

	private final String insertIntoNvdData = "INSERT INTO nvd_data (cve_id, published_date) VALUES (?, ?)";

	private final String checkIfInNVD = "SELECT COUNT(*) as numInNvd FROM nvd_data WHERE cve_id = ?";

	private final String insertCrawledData = "";

	private static DatabaseHelper databaseHelper = null;
	private static Map<String, Vulnerability> existingVulnMap = new HashMap<>();

	/**
	 * Thread safe singleton implementation
	 * 
	 * @return
	 */
	public static synchronized DatabaseHelper getInstance() {
		if (databaseHelper == null)
			databaseHelper = new DatabaseHelper();

		return databaseHelper;
	}

	/**
	 * The private constructor sets up HikariCP for connection pooling.
	 * Singleton DH!
	 */
	private DatabaseHelper() {
		try {
			logger.info("New NVIP.DatabaseHelper instantiated! It is configured to use " + databaseType + " database!");
			if (databaseType.equalsIgnoreCase("mysql"))
				Class.forName("com.mysql.cj.jdbc.Driver");

		} catch (ClassNotFoundException e2) {
			logger.error("Error while loading database type from the nvip.properties! " + e2.toString());
		}

		String configFile = "db-" + databaseType + ".properties";

		if(config == null){
			logger.info("Attempting to create HIKARI from ENVVARs");
			config = createHikariConfigFromEnvironment();
		}

		if(config == null){
			config = createHikariConfigFromProperties(configFile);
		}

		try {

			dataSource = new HikariDataSource(config); // init data source
		} catch (PoolInitializationException e2) {
			logger.error("Error initializing data source! Check the value of the database user/password in the config file '{}'! Current values are: {}", configFile, config.getDataSourceProperties());
			System.exit(1);

		}
	}

	private HikariConfig createHikariConfigFromEnvironment() {

		String url = System.getenv("HIKARI_URL");
		HikariConfig hikariConfig;

		if (url != null){
			logger.info("Creating HikariConfig with url={}", url);
			hikariConfig = new HikariConfig();
			hikariConfig.setJdbcUrl(url);
			hikariConfig.setUsername(System.getenv("HIKARI_USER"));
			hikariConfig.setPassword(System.getenv("HIKARI_PASSWORD"));

			System.getenv().entrySet().stream()
					.filter(e -> e.getKey().startsWith("HIKARI_"))
					.peek(e -> logger.info("Setting {} to HikariConfig", e.getKey()))
					.forEach(e -> hikariConfig.addDataSourceProperty(e.getKey(), e.getValue()));

		} else {
			hikariConfig = null;
		}

		return hikariConfig;
	}

	private HikariConfig createHikariConfigFromProperties(String configFile) {
		HikariConfig config;
		try {
			Properties props = new Properties();
			try {
				// get config file from the root path
				try (InputStream inputStream = new FileInputStream(configFile)) {
					props.load(inputStream);
					logger.info("DatabaseHelper initialized using config file {} at {}", configFile,
							System.getProperty("user.dir"));
				}
			} catch (FileNotFoundException e) {
				String currDir = System.getProperty("user.dir");
				logger.warn("Could not locate db config file in the root path \"{}\", getting it from resources! Warning: {}",
						currDir, e.getMessage());
				ClassLoader loader = Thread.currentThread().getContextClassLoader();

				try (InputStream inputStream = loader.getResourceAsStream(configFile)) {
					props.load(inputStream);
				}

			}

			config = new HikariConfig(props);
			config.setMaximumPoolSize(50);
		} catch (Exception e1) {
			logger.warn(
					"Could not load db.properties(" + configFile + ") from src/main/resources! Looking at the root path now!");
			config = new HikariConfig("db-" + databaseType + ".properties"); // in the production system get it from the
			// root dir
		}

		return config;
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
	 * Get existing vulnerabilities hash map. This method was added to improve
	 * DatabaseHelper, NOT to query each CVEID during a CVE update! Existing
	 * vulnerabilities are read only once, and this hash map is queried during
	 * individual update operations!
	 * 
	 * @return
	 */
	public Map<String, Vulnerability> getExistingVulnerabilities() {

		if (existingVulnMap.size() == 0) {
			synchronized (DatabaseHelper.class) {
				if (existingVulnMap.size() == 0) {
					int vulnId;
					String cveId, description, createdDate;
					int existAtNvd, existAtMitre;
					existingVulnMap = new HashMap<>();
					try (Connection connection = getConnection();) {

						String selectSql = "SELECT vuln_id, cve_id, description, created_date, exists_at_nvd, exists_at_mitre from vulnerability";
						PreparedStatement pstmt = connection.prepareStatement(selectSql);
						ResultSet rs = pstmt.executeQuery();

						while (rs.next()) {
							vulnId = rs.getInt("vuln_id");
							cveId = rs.getString("cve_id");
							description = rs.getString("description");
							createdDate = rs.getString("created_date");
							existAtNvd = rs.getInt("exists_at_nvd");
							existAtMitre = rs.getInt("exists_at_mitre");
							Vulnerability existingVulnInfo = new Vulnerability(vulnId, cveId, description, existAtNvd, existAtMitre,
									createdDate);
							existingVulnMap.put(cveId, existingVulnInfo);
						}
						logger.info("NVIP has loaded {} existing CVE items from DB!", existingVulnMap.size());
					} catch (Exception e) {
						logger.error("Error while getting existing vulnerabilities from DB\nException: {}", e.getMessage());
						logger.error(
								"This is a serious error! NVIP will not be able to decide whether to insert or update! Exiting...");
						System.exit(1);
					}
				}
			}
		} else {
			logger.warn("NVIP has loaded {} existing CVE items from memory!", existingVulnMap.size());
		}

		return existingVulnMap;
	}

	/**
	 * For Inserting a Vulnerability into the vulnerability table
	 */
	public void insertVulnerability(RawVulnerability vuln) {
		try (Connection connection = getConnection(); PreparedStatement pstmt = connection.prepareStatement(insertVulnSql);) {

			pstmt.setString(1, vuln.getCveId());
			pstmt.setString(2, vuln.getDescription());
			pstmt.setString(3, vuln.getPlatform());
			pstmt.setString(4, vuln.getPatch());
			pstmt.setString(5, vuln.getPublishDate().toString());

			pstmt.setString(6, vuln.getLastModifiedDate().toString()); // during insert create date is last modified date
			pstmt.setString(7, vuln.getLastModifiedDate().toString());
			pstmt.setString(8, vuln.getFixDate().toString());
			/**
			 * Bug fix: indexes 9 and 10 were wrong
			 */
			pstmt.setInt(9, vuln.getNvdStatus());
			pstmt.setInt(10, vuln.getMitreStatus());
			pstmt.setInt(11, vuln.getTimeGapNvd());
			pstmt.setInt(12, vuln.getTimeGapMitre());
			pstmt.executeUpdate();
		} catch (Exception e) {
			logger.error("ERROR: Failed to insert CVE: {}\n{}", vuln.getCveId(), e.toString());
		}
	}


	/**
	 * Updates the Vulnerability table with the Vulnerability object (vuln) passed
	 * in.
	 * 
	 * @param vuln            Vulnerability object to be updated in database
	 * @throws SQLException
	 */
	public int updateVulnerability(RawVulnerability vuln) throws SQLException {

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(updateVulnSql)) {
			// update vulnerability
			pstmt.setString(1, vuln.getDescription());
			pstmt.setString(2, vuln.getPlatform());
			pstmt.setString(3, vuln.getPatch());
			pstmt.setString(4, vuln.getPublishDate());
			pstmt.setString(5, vuln.getLastModifiedDate());
			pstmt.setString(6, vuln.getFixDate());
			pstmt.setString(7, vuln.getCveId()); // WHERE clause in SQL statement

			pstmt.executeUpdate();
		} catch (Exception e1) {
			// you may still continue updating other vuln attribs below!
			logger.error("Error while updating CVE: {} Exception: {}:{}", vuln.getCveId(), e1.toString(), e1.getMessage());
		}

		return 1;
	}

	/**
	 * insert a vulnerability column value
	 * 
	 * @param vulnId
	 * @param columnName
	 * @param columnValue
	 * @param runId
	 * @return
	 */
	public boolean insertVulnerabilityUpdate(int vulnId, String columnName, String columnValue, int runId) {
		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(insertVulnerabilityUpdateSql)){
			pstmt.setInt(1, vulnId);
			pstmt.setString(2, columnName);
			pstmt.setString(3, columnValue);
			pstmt.setInt(4, runId);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error("Error while logging vuln updates!\n{}", e.getMessage());
			return false;
		}
		return true;
	}

	/**
	 * Record CVE status changes in NVD/MITRE
	 * 
	 * @param vuln
	 * @param existingAttribs
	 * @param comparedAgainst
	 * @param oldStatus
	 * @param newStatus
	 * @param timeGapFound
	 * @param timeGap
	 */
	public boolean addToCveStatusChangeHistory(RawVulnerability vuln,
			Vulnerability existingAttribs, String comparedAgainst, int oldStatus, int newStatus,
			boolean timeGapFound, int timeGap) {

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(insertCveStatusSql);) {
			pstmt.setInt(1, existingAttribs.getVulnID());
			pstmt.setString(2, vuln.getCveId());
			pstmt.setString(3, comparedAgainst);
			pstmt.setInt(4, oldStatus);
			pstmt.setInt(5, newStatus);
			pstmt.setString(6, vuln.getDescription());

			int timeGapRecorded = (timeGapFound) ? 1 : 0;
			pstmt.setInt(7, timeGapRecorded);
			pstmt.setInt(8, timeGap);
			try {
				pstmt.setTimestamp(9, new Timestamp(longDateFormatMySQL.parse(vuln.getLastModifiedDate()).getTime()));
			} catch (Exception e) {
				logger.warn("WARNING: Failed to parse last modified date: {}", vuln.getLastModifiedDate());
				pstmt.setTimestamp(9, new Timestamp(longDateFormatMySQL.parse(vuln.getPublishDate()).getTime()));
			}
			pstmt.setTimestamp(10, new Timestamp(longDateFormatMySQL.parse(existingAttribs.getCreateDate()).getTime()));
			pstmt.executeUpdate();
		} catch (Exception e) {
			logger.error("Error recording CVE status change for {}:\n{}", vuln.getCveId(), e);
			return false;
		}

		return true;
	}

	/**
	 * For Updating the Nvd status of a CVE
	 * @param newStatus
	 * @param cveId
	 */
	public void updateNvdStatus(int newStatus, String cveId) {
		try (Connection connection = getConnection();
			PreparedStatement pstmt = connection.prepareStatement(updateNvdStatusSql)) {
			pstmt.setInt(1,newStatus);
			pstmt.setString(2, cveId);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error("ERROR: Failed to update NVD Status for CVE: {}\n{}", cveId, e);
		}
	}

	/**
	 * For Updating the Mitre status of a CVE
	 * @param newstatus
	 * @param cveId
	 */
	public void updateMitreStatus(int newstatus, String cveId) {
		try (Connection connection = getConnection();
			PreparedStatement pstmt = connection.prepareStatement(updateMitreStatusSql);) {
			pstmt.setInt(1, newstatus);
			pstmt.setString(2, cveId);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error("ERROR: Failed to update Mitre Status for CVE: {}\n{}", cveId, e);
		}
	}

	/**
	 * For Updating the NVD time gap in a vulnerability
	 * @param timeGap
	 * @param cveId
	 */
	public void updateNvdTimeGap(int timeGap, String cveId) {
		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(updateNvdTimeGapSql)) {
			pstmt.setInt(1, timeGap);
			pstmt.setString(2, cveId);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error("ERROR: Failed to update Mitre Status for CVE: {}\n{}", cveId, e);
		}
	}

	/**
	 * For updating MITRe time gaps in a vulnerability
	 * @param timeGap
	 * @param cveId
	 */
	public void updateMitreTimeGap(int timeGap, String cveId) {
		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(updateMitreTimeGapSql)) {
			pstmt.setInt(1, timeGap);
			pstmt.setString(2, cveId);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error("ERROR: Failed to update Mitre Status for CVE: {}\n{}", cveId, e);
		}
	}

	/**
	 * Returns an ArrayList of NvipSource objects gathered from all rows in the
	 * NvipSourceUrl table.
	 * 
	 * @return A list of all NvipSource in the NvipSourceUrl table
	 */
	public ArrayList<NvipSource> getNvipCveSources() {
		ArrayList<NvipSource> nvipSourceList = new ArrayList<NvipSource>();
		Connection conn = null;
		try {
			conn = getConnection();
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(selectAllNvipSourceSql);

			while (rs.next()) {
				int sourceId = rs.getInt("source_id");
				String url = rs.getString("url");
				String description = rs.getString("description");
				int httpStatus = rs.getInt("http_status");

				NvipSource nvipSource = new NvipSource(url, description, httpStatus);
				nvipSource.setSourceId(sourceId);
				nvipSourceList.add(nvipSource);
			}
		} catch (SQLException e) {
			logger.error(e.getMessage());
		} finally {
			try {
				conn.close();
			} catch (SQLException ignored) {

			}
		}

		return nvipSourceList;
	}

	/**
	 * With the same connection
	 * 
	 * @param vulnSourceList
	 * @return
	 */
	public boolean insertVulnSource(List<VulnSource> vulnSourceList) {
		try (Connection connection = getConnection(); PreparedStatement pstmt = connection.prepareStatement(insertVulnSourceSql);) {
			for (int i = 0; i < vulnSourceList.size(); i++) {
				pstmt.setString(1, vulnSourceList.get(i).getCveId());
				pstmt.setString(2, vulnSourceList.get(i).getUrl());
				pstmt.executeUpdate();
			}
		} catch (SQLException e) {
			logger.error(e.getMessage());
			return false;
		}
		return true;
	}

	/**
	 * delete sources for the given cve id
	 * 
	 * @param cveId
	 * @return
	 */
	public int deleteVulnSource(String cveId) {
		Connection conn = null;
		try {
			conn = getConnection();
			PreparedStatement pstmt = conn.prepareStatement(deleteVulnSourceSql);
			pstmt.setString(1, cveId);
			int count = pstmt.executeUpdate();
			return count;
		} catch (SQLException e) {
			logger.error("Error in (): " + e.getMessage());
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {

			}
		}
		return 0;
	}

	/**
	 * Inserts <dailyRun> into the DailyRunHistory table in the database.
	 * 
	 * @param dailyRun
	 * @return max run_id
	 */
	public int insertDailyRun(DailyRun dailyRun) {
		logger.info("Inserting Daily Run Stats...");
		ResultSet rs;
		int maxRunId = -1;
		Connection conn = null;
		try {
			conn = getConnection();
			Statement stmt = conn.createStatement();

			PreparedStatement pstmt = conn.prepareStatement(insertDailyRunSql);
			pstmt.setString(1, dailyRun.getRunDateTime());
			pstmt.setFloat(2, dailyRun.getCrawlTimeMin());
			pstmt.setInt(3, dailyRun.getTotalCveCount());
			pstmt.setInt(4, dailyRun.getNotInNvdCount());
			pstmt.setInt(5, dailyRun.getNotInMitreCount());
			pstmt.setInt(6, dailyRun.getNotInBothCount());
			pstmt.setInt(7, dailyRun.getNewCveCount());
			pstmt.setDouble(8, dailyRun.getAvgTimeGapNvd());
			pstmt.setDouble(9, dailyRun.getAvgTimeGapMitre());
			pstmt.setInt(10, dailyRun.getAddedCveCount());
			pstmt.setInt(11, dailyRun.getUpdatedCveCount());
			pstmt.executeUpdate();

			logger.info("Daily Run Stats Inputted Successfully!");

			String maxRunIdSQL = "SELECT max(run_id) as run_id FROM dailyrunhistory";
			rs = stmt.executeQuery(maxRunIdSQL);
			if (rs.next()) {
				maxRunId = rs.getInt("run_id");
			}

		} catch (Exception e) {
			logger.error("ERROR: Error when trying to input Daily Run Stats\n{}", e.toString());
		} finally {
			try {
				conn.close();
			} catch (SQLException e) {
				logger.error("ERROR: Error when trying to close connection for Daily Run Stats\n{}", e.toString());
			}
		}
		return maxRunId;
	}


	/**
	 * update DailyRun
	 * 
	 * @param runId
	 * @param dailyRun
	 * @return
	 */
	public int updateDailyRun(int runId, DailyRun dailyRun) {
		Connection conn = null;
		PreparedStatement pstmt = null;
		DecimalFormat df = new DecimalFormat("#.00");
		try {
			conn = getConnection();
			/**
			 * calculate avg nvd and mitre times
			 */
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(this.selectAverageTimeGapMitre);
			if (rs.next())
				dailyRun.setAvgTimeGapMitre(Double.parseDouble(formatter.format(rs.getDouble("gapMitre"))));

			rs = stmt.executeQuery(this.selectAverageTimeGapNvd);
			if (rs.next())
				dailyRun.setAvgTimeGapNvd(Double.parseDouble(formatter.format(rs.getDouble("gapNvd"))));

			pstmt = conn.prepareStatement(updateDailyRunSql);

			float crawlTime = Float.parseFloat(df.format(dailyRun.getCrawlTimeMin()));
			pstmt.setFloat(1, crawlTime);
			double dbTime = Double.parseDouble(df.format(dailyRun.getDatabaseTimeMin()));

			pstmt.setDouble(2, dbTime);
			pstmt.setInt(3, dailyRun.getTotalCveCount());
			pstmt.setInt(4, dailyRun.getNotInNvdCount());
			pstmt.setInt(5, dailyRun.getNotInMitreCount());
			pstmt.setInt(6, dailyRun.getNotInBothCount());
			pstmt.setInt(7, dailyRun.getNewCveCount());
			double avgNvdTime = Double.parseDouble(df.format(dailyRun.getAvgTimeGapNvd()));
			pstmt.setDouble(8, avgNvdTime);

			double avgMitreTime = Double.parseDouble(df.format(dailyRun.getAvgTimeGapMitre()));
			pstmt.setDouble(9, avgMitreTime);
			pstmt.setInt(10, runId);
			pstmt.executeUpdate();

			logger.info("AVG NVD TIME: {}", avgNvdTime);
			logger.info("AVG MITRE TIME: {}", avgMitreTime);

		} catch (Exception e) {
			try {
				logger.error("Error in updateDailyRun()!  " + e.getMessage() + "\nSQL:" + pstmt.toString());
			} catch (Exception e2) {
				logger.error("Error in updateDailyRun()! " + e.getMessage() + "\n" + e2.getMessage());
			}
		} finally {
			try {
				if (conn != null)
					conn.close();
			} catch (SQLException e) {

			}
		}
		return runId;
	}

	/**
	 * Insert vdo characteristic
	 * 
	 * @param vdoCharacteristicList
	 * @return
	 */
	public boolean insertVdoCharacteristic(List<VdoCharacteristic> vdoCharacteristicList) {
		try (Connection conenction = getConnection();
			 PreparedStatement pstmt = conenction.prepareStatement(insertVdoCharacteristicSql);){
			for (int i = 0; i < vdoCharacteristicList.size(); i++) {

				pstmt.setString(1, vdoCharacteristicList.get(i).getCveId());
				pstmt.setInt(2, vdoCharacteristicList.get(i).getVdoLabelId());
				pstmt.setDouble(3, vdoCharacteristicList.get(i).getVdoConfidence());
				pstmt.setInt(4, vdoCharacteristicList.get(i).getVdoNounGroupId());
				pstmt.executeUpdate();
			}

		} catch (SQLException e) {
			logger.error("Error inserting VDO characterization: " + e.getMessage());
			return false;
		}
		return true;
	}

	/**
	 * Flush VDO data for CVE
	 * 
	 * @param cveId
	 * @param vdoCharacteristicList
	 */
	public void updateVdoLabels(String cveId, List<VdoCharacteristic> vdoCharacteristicList) {

		// Delete existing VDO Labels
		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(deleteVdoCharacteristicSql);) {
			pstmt.setString(1, cveId);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error(e.toString());
		}

		// Insert new ones
		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(insertVdoCharacteristicSql);) {
			for (int i = 0; i < vdoCharacteristicList.size(); i++) {
				pstmt.setString(1, vdoCharacteristicList.get(i).getCveId());
				pstmt.setInt(2, vdoCharacteristicList.get(i).getVdoLabelId());
				pstmt.setDouble(3, vdoCharacteristicList.get(i).getVdoConfidence());
				pstmt.setInt(4, vdoCharacteristicList.get(i).getVdoNounGroupId());
				pstmt.executeUpdate();
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		}

	}

	/**
	 * Insert cvss scores
	 * 
	 * @param cvssScoreList
	 * @return
	 */
	public void insertCvssScore(List<CvssScore> cvssScoreList) {

		for (int i = 0; i < cvssScoreList.size(); i++) {
			try (Connection connection = getConnection();
				 PreparedStatement pstmt = connection.prepareStatement(insertCvssScoreSql);) {
				pstmt.setString(1, cvssScoreList.get(i).getCveId());
				pstmt.setInt(2, cvssScoreList.get(i).getSeverityId());
				pstmt.setDouble(3, cvssScoreList.get(i).getSeverityConfidence());
				pstmt.setString(4, cvssScoreList.get(i).getImpactScore());
				pstmt.setDouble(5, cvssScoreList.get(i).getImpactConfidence());
				pstmt.executeUpdate();
			} catch (SQLException e) {
				logger.error(e.toString());
			}
		}
	}

	/**
	 * Delete cvss for cve
	 * 
	 * @param cveId
	 * @return
	 */
	public int deleteCvssScore(String cveId) {
		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(deleteCvssScoreSql);) {
			pstmt.setString(1, cveId);
			return pstmt.executeUpdate();
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		return 0;
	}

	/**
	 * IMPORTANT NOTE: Please do not use this method. Use getInstance() instead.
	 * This method is used while storing tens of thousands of CVEs with
	 * multi-threading.
	 * 
	 * 
	 * If you need to use this method, do not forget to invoke shutdown() when you
	 * are done!
	 * 
	 * @return
	 */
	public static DatabaseHelper getInstanceForMultiThreading() {
		return new DatabaseHelper();
	}

	/**
	 * Hikari active connections
	 * 
	 * @return
	 */
	public int getActiveConnections() {
		return dataSource.getHikariPoolMXBean().getActiveConnections();
	}

	/**
	 * Hikari idle connections
	 * 
	 * @return
	 */
	public int getIdleConnections() {
		return dataSource.getHikariPoolMXBean().getIdleConnections();
	}

	/**
	 * Hikari total connections!
	 * 
	 * @return
	 */
	public int getTotalConnections() {
		return dataSource.getHikariPoolMXBean().getTotalConnections();
	}

	/**
	 * active, idle and total connections on the current instance
	 * 
	 * @return
	 */
	public String getConnectionStatus() {
		return "[" + getActiveConnections() + "," + this.getIdleConnections() + "]=" + getTotalConnections();
	}

	/**
	 * shut down connection pool. U
	 */
	public void shutdown() {
		dataSource.close();
		config = null;
	}

	/**
	 * clear existing CVEs map
	 */
	public static void clearExistingVulnMap() {
		existingVulnMap.clear();
	}

	/**
	 * get vulnerability Id(s) of the CVE
	 * 
	 * @param cveId
	 * @return
	 */
	public List<Integer> getVulnerabilityIdList(String cveId) {
		List<Integer> vulnIdList = new ArrayList<Integer>();
		ResultSet rs;

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(selectVulnerabilityIdSql)){

			pstmt.setString(1, cveId);
			rs = pstmt.executeQuery();
			while (rs.next()) {
				vulnIdList.add(rs.getInt("vuln_id"));
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		return vulnIdList;
	}

	/**
	 * Collect a CVE ID from the Vulnerability table by Vuln ID
	 * 
	 * @param vulnId
	 * @return
	 */
	public String getCveId(String vulnId) {

		String cve_id = "";

		try (Connection connection = getConnection()) {

			PreparedStatement pstmt = connection.prepareStatement(selectCVEIdSql);
			pstmt.setInt(1, Integer.parseInt(vulnId));
			ResultSet rs = pstmt.executeQuery();

			if (rs.next()) {
				cve_id = rs.getString("cve_id");
			}
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return cve_id;
	}


	/**
	 * For Inserting a CVe from NVD into nvd_data table
	 * @param cveId
	 * @param publishedDate
	 * @return
	 */
	public int insertNvdCve(String cveId, String publishedDate) {

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(insertIntoNvdData);) {

			pstmt.setString(1, cveId);
			pstmt.setTimestamp(2, Timestamp.valueOf(publishedDate));

			pstmt.execute();

			logger.info("Successfully Inserted CVE {} with Published Date {} into nvd_data", cveId, publishedDate);

			return 1;
		} catch (Exception e) {
			logger.error("ERROR: Failed to insert CVE {} with Published Date {} into nvd_data table", cveId, publishedDate);
		}

		return 0;
	}

	/**
	 * Check if a CVE is in NVD
	 * @return
	 */
	public boolean checkIfInNvd(String cveId) {
		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(checkIfInNVD);) {

			pstmt.setString(1, cveId);

			ResultSet rs = pstmt.executeQuery();
			if (rs.next())
				return rs.getInt("numInNvd") > 0;

		} catch (Exception e) {
			logger.error("ERROR: Failed to insert CVE {} with Published Date {} into nvd_data table", cveId);
		}

		return false;
	}

	private final String insertRawData = "INSERT INTO rawdescription (raw_description, cve_id, created_date, published_date, last_modified_date, source_url) " +
			"VALUES (?, ?, ?, ?, ?, ?)";

	/**
	 * for inserting crawled data to rawdescriptions
	 * @param vuln
	 * @return
	 */
	public int insertRawVulnerability(RawVulnerability vuln) {
		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(insertRawData);) {

			pstmt.setString(1, vuln.getDescription());
			pstmt.setString(2, vuln.getCveId());
			pstmt.setTimestamp(3, Timestamp.valueOf(vuln.getCreatedDateAsDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
			pstmt.setTimestamp(4, Timestamp.valueOf(vuln.getPublishDateAsDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
			pstmt.setTimestamp(5, Timestamp.valueOf(vuln.getLastModifiedDateAsDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
			pstmt.setString(6, vuln.getSourceURL());

			pstmt.execute();

			return 1;
		} catch (Exception e) {
			logger.error("ERROR: Failed to insert data for CVE {} into rawdescription table\n{}", vuln.getCveId(), e);
		}

		return 0;
	}

	private final String checkIfInRawDesc = "SELECT COUNT(*) numInRawDesc FROM rawdescription WHERE raw_description = ?";

	/**
	 * For checking if a description is already in rawdescription
	 * Compares descriptions for now
	 * @return
	 */
	public boolean checkIfInRawDescriptions(String description) {

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(checkIfInRawDesc)) {
			pstmt.setString(1, description);
			ResultSet rs = pstmt.executeQuery();

			if (rs.next())
				return rs.getInt("numInRawDesc") > 0;
		} catch (Exception e) {
			logger.error("ERROR: Failed to check description {} in rawdescription table\n{}", description, e);
		}

		return false;

	}

	private final String insertCVEJob = "INSERT INTO cvejobtrack (cve_id) VALUES (?, ?) ";

	/**
	 * Add status for CVE in Job Tracker Table
	 * @param cveId
	 */
	public void addJobForCVE(String cveId) {

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(insertCVEJob)) {
			pstmt.setString(1, cveId);
			pstmt.executeUpdate();

		} catch (Exception e) {
			logger.error("ERROR: Failed to add CVE {} in cvejobtrack table\n{}", cveId, e);
		}

	}

}