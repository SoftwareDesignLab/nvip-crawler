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
package db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.pool.HikariPool.PoolInitializationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * 
 * The DatabaseHelper class is used to insert and update vulnerabilities found
 * from the webcrawler/processor to a sqlite database
 */
public class DatabaseHelper {
	private HikariConfig config = null;
	private HikariDataSource dataSource;
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	final String databaseType;

	private final String selectCpesAndCve = "SELECT v.cve_id, p.cpe FROM vulnerability v LEFT JOIN affectedrelease ar ON ar.cve_id = v.cve_id LEFT JOIN product p ON p.product_id = ar.product_id WHERE p.cpe IS NOT NULL;";
	private final String getVulnIdByCveId = "SELECT vuln_id FROM vulnerability WHERE cve_id = ?";
	private final String insertPatchSourceURLSql = "INSERT INTO patchsourceurl (vuln_id, source_url) VALUES (?, ?);";
	private final String insertPatchCommitSql = "INSERT INTO patchcommit (source_id, commit_url, commit_date, commit_message) VALUES (?, ?, ?, ?);";

	/**
	 * The private constructor sets up HikariCP for connection pooling. Singleton
	 * DP!
	 */
	public DatabaseHelper() {
		// Get database type from envvars
		databaseType = System.getenv("DB_TYPE");
		logger.info("New NVIP.DatabaseHelper instantiated! It is configured to use " + databaseType + " database!");

		try {
			if (databaseType.equalsIgnoreCase("mysql"))
				Class.forName("com.mysql.cj.jdbc.Driver");
		} catch (ClassNotFoundException e2) {
			logger.error("Error while loading database type from environment variables! " + e2.toString());
		}

		if(config == null){
			logger.info("Attempting to create HIKARI from ENVVARs");
			config = createHikariConfigFromEnvironment();
		}

		try {
			if(config == null) throw new IllegalArgumentException();
			dataSource = new HikariDataSource(config); // init data source
		} catch (PoolInitializationException e2) {
			logger.error("Error initializing data source! Check the value of the database user/password in the environment variables! Current values are: {}", config != null ? config.getDataSourceProperties() : null);
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
	 * Shut down connection pool.
	 */
	public void shutdown() {
		dataSource.close();
		config = null;
	}

	/**
	 * Collects a map of CPEs with their correlated CVE and Vuln ID used for
	 * collecting patches
	 *
	 * @return
	 */
	public Map<String, ArrayList<String>> getCPEsAndCVE() {
		Map<String, ArrayList<String>> cpes = new HashMap<>();
		try (Connection conn = getConnection();
			 PreparedStatement pstmt = conn.prepareStatement(selectCpesAndCve);) {

			ResultSet res = pstmt.executeQuery();

			while (res.next()) {

				String cveId = res.getString("cve_id");
				String cpe = res.getString("cpe");

				if (cpes.containsKey(cveId)) {
					cpes.get(cveId).add(cpe);
				} else {
					ArrayList<String> data = new ArrayList<>();
					data.add(cpe);
					cpes.put(cveId, data);
				}
			}

		} catch (Exception e) {
			logger.error("ERROR: Failed to grab CVEs and CPEs from DB:\n{}", e);
		}

		return cpes;
	}

	/**
	 * Collects the vulnId for a specific CVE with a given CVE-ID
	 *
	 * @param cveId
	 * @return
	 */
	public int getVulnIdByCveId(String cveId) {
		int result = -1;
		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(getVulnIdByCveId);) {
			pstmt.setString(1, cveId);
			ResultSet rs = pstmt.executeQuery();
			if (rs.next()) {
				result = rs.getInt("vuln_id");
			}
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return result;
	}

	/**
	 * Inserts given source URL into the patch source table
	 *
	 * @param vuln_id
	 *
	 * @return
	 */
	public boolean insertPatchSourceURL(int vuln_id, String sourceURL) {
		try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(insertPatchSourceURLSql);) {
			pstmt.setInt(1, vuln_id);
			pstmt.setString(2, sourceURL);
			pstmt.executeUpdate();

			logger.info("Inserted PatchURL: " + sourceURL);
			conn.close();
			return true;
		} catch (Exception e) {
			logger.error("ERROR: Failed to insert patch source with sourceURL {} for vuln id {}\n{}", sourceURL,
					vuln_id, e.getMessage());
			return false;
		}
	}

	/**
	 * Method for inserting a patch commit into the patchcommit table
	 *
	 * @param sourceId
	 * @param sourceURL
	 * @param commitId
	 * @param commitDate
	 * @param commitMessage
	 */
	public void insertPatchCommit(int sourceId, String sourceURL, String commitId, LocalDateTime commitDate, String commitMessage) {

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(insertPatchCommitSql);) {

			pstmt.setInt(1, sourceId);
			pstmt.setString(2, sourceURL + "/commit/" + commitId);
			pstmt.setDate(3, java.sql.Date.valueOf(commitDate.toString()));
			pstmt.setString(4, commitMessage);
			pstmt.executeUpdate();
		} catch (Exception e) {
			logger.error("ERROR: failed to insert patch commit from source {}\n{}", sourceURL, e);
		}
	}
}