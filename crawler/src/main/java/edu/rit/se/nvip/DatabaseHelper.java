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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 
 * The DatabaseHelper class is used to insert and update vulnerabilities found
 * from the webcrawler/processor to a sqlite database
 */
public class DatabaseHelper {
	private HikariConfig config = null;
	private HikariDataSource dataSource;
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	String databaseType = "mysql";

	private final String selectAllNvipSourceSql = "SELECT * FROM nvipsourceurl;";

	private final String insertVulnerabilityUpdateSql = "INSERT INTO vulnerabilityupdate (vuln_id, column_name, column_value, run_id) VALUES (?,?,?,?);";
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

	private final String checkIfInRawDesc = "SELECT COUNT(*) numInRawDesc FROM rawdescription WHERE cve_id = ? AND raw_description = ?";

	/**
	 * For checking if a description is already in rawdescription
	 * Compares descriptions for now
	 * @return
	 */
	public boolean checkIfInRawDescriptions(String cveId, String description) {

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(checkIfInRawDesc)) {
			pstmt.setString(1, cveId);
			pstmt.setString(2, description);
			ResultSet rs = pstmt.executeQuery();

			if (rs.next())
				return rs.getInt("numInRawDesc") > 0;
		} catch (Exception e) {
			logger.error("ERROR: Failed to check description {} in rawdescription table\n{}", description, e);
		}

		return false;

	}

	private final String insertCVEJob = "INSERT INTO cvejobtrack (cve_id) VALUES (?) ";

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

	private final String checkifInJobTrack = "SELECT COUNT(*) numInJobtrack FROM cvejobtrack WHERE cve_id = ?";

	/**
	 * Checks if a CVEID is already in cvejobtrack table
	 * @param cveId
	 * @return
	 */
	public boolean isCveInJobTrack(String cveId) {

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(checkifInJobTrack)) {
			pstmt.setString(1, cveId);
			ResultSet rs = pstmt.executeQuery();

			if (rs.next())
				return rs.getInt("numInJobtrack") > 0;
		} catch (Exception e) {
			logger.error("ERROR: Failed to check CVE {} in cvejobtrack table\n{}", cveId, e);
		}

		return false;

	}

	private final String getRawCVEs = "SELECT DISTINCT cve_id, published_date FROM rawdescription order by cve_id desc";

	/**
	 * For getting raw CVE Data for NVD Comparison
	 * @return
	 */
	public HashMap<String, LocalDateTime> getRawCVEForNVDComparisons() {

		HashMap<String, LocalDateTime> rawCves = new HashMap<>();

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(getRawCVEs)) {
			ResultSet rs = pstmt.executeQuery();

			while (rs.next()) {
				rawCves.put(rs.getString("cve_id"), rs.getTimestamp("published_date").toLocalDateTime());
			}
		} catch (Exception e) {
			logger.error("ERROR: Failed to grab raw CVEs from rawdescription table\n{}", e);
		}

		return rawCves;
	}

}