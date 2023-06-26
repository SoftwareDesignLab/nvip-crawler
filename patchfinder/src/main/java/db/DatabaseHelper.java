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
import model.CpeEntry;
import model.CpeGroup;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.*;
import java.time.Instant;
import java.sql.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 
 * The DatabaseHelper class is used to insert and update vulnerabilities found
 * from the webcrawler/processor to a sqlite database
 */
public class DatabaseHelper {
	private HikariConfig config = null;
	private HikariDataSource dataSource;
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	private final String selectAffectedProducts = "SELECT cve_id, cpe FROM affectedproduct GROUP BY product_name, affected_product_id ORDER BY cve_id DESC, version ASC;";
	private final String getVulnIdByCveId = "SELECT vuln_id FROM vulnerability WHERE cve_id = ?";
	private final String insertPatchSourceURLSql = "INSERT INTO patchsourceurl (cve_id, source_url) VALUES (?, ?);";
	private final String insertPatchCommitSql = "INSERT INTO patchcommit (source_url_id, commit_url, commit_date, commit_message, uni_diff) VALUES (?, ?, ?, ?, ?);";
	// Regex101: https://regex101.com/r/9uaTQb/1
	public static final Pattern CPE_PATTERN = Pattern.compile("cpe:2\\.3:[aho\\*\\-]:([^:]*):([^:]*):([^:]*):.*");

	/**
	 * The private constructor sets up HikariCP for connection pooling. Singleton
	 * DP!
	 */
	public DatabaseHelper(String databaseType, String hikariUrl, String hikariUser, String hikariPassword) {
		logger.info("New NVIP.DatabaseHelper instantiated! It is configured to use " + databaseType + " database!");

		try {
			if (databaseType.equalsIgnoreCase("mysql"))
				Class.forName("com.mysql.cj.jdbc.Driver");
		} catch (ClassNotFoundException e2) {
			logger.error("Error while loading database type from environment variables! " + e2.toString());
		}

		if(config == null){
			logger.info("Attempting to create HIKARI from ENVVARs");
			config = createHikariConfig(hikariUrl, hikariUser, hikariPassword);
		}

		try {
			if(config == null) throw new IllegalArgumentException("Failed to create HIKARI from ENVVARs");
			dataSource = new HikariDataSource(config); // init data source
		} catch (PoolInitializationException e2) {
			logger.error("Error initializing data source! Check the value of the database user/password in the environment variables! Current values are: {}", config != null ? config.getDataSourceProperties() : null);
			System.exit(1);

		}
	}

	private HikariConfig createHikariConfig(String url, String user, String password) {
		HikariConfig hikariConfig;

		if (url != null){
			logger.info("Creating HikariConfig with url={}", url);
			hikariConfig = new HikariConfig();
			hikariConfig.setJdbcUrl(url);
			hikariConfig.setUsername(user);
			hikariConfig.setPassword(password);
			hikariConfig.addDataSourceProperty("HIKARI_URL", url);
			hikariConfig.addDataSourceProperty("HIKARI_USER", user);
			hikariConfig.addDataSourceProperty("HIKARI_PASSWORD", password);

//			System.getenv().entrySet().stream()
//					.filter(e -> e.getKey().startsWith("HIKARI_"))
//					.peek(e -> logger.info("Setting {} to HikariConfig", e.getKey()))
//					.forEach(e -> hikariConfig.addDataSourceProperty(e.getKey(), e.getValue()));

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
	 * @return a map of affected products
	 */
	public Map<String, CpeGroup> getAffectedProducts() {
		Map<String, CpeGroup> affectedProducts = new HashMap<>();
		// Prepare statement
		try (Connection conn = getConnection();
			 PreparedStatement pstmt = conn.prepareStatement(selectAffectedProducts)
		) {
			// Execute and get result set
			ResultSet res = pstmt.executeQuery();

			// Parse results
			while (res.next()) {
				// Extract cveId and cpe from result
				final String cveId = res.getString("cve_id");
				final String cpe = res.getString("cpe");

				// Extract product name and version from cpe
				final Matcher m = CPE_PATTERN.matcher(cpe);
				if(!m.find()) {
					logger.warn("Invalid cpe '{}' could not be parsed, skipping product", cpe);
					continue;
				}
				final String vendor = m.group(1);
				final String name = m.group(2);
				final String version = m.group(3);
				final CpeEntry entry = new CpeEntry(name, version, cpe);

				// If we already have this cveId stored, add specific version
				if (affectedProducts.containsKey(cveId)) {
					affectedProducts.get(cveId).addVersion(entry);
				} else {
					final CpeGroup group = new CpeGroup(vendor, name);
					group.addVersion(entry);
					affectedProducts.put(cveId, group);
				}
			}

		} catch (Exception e) {
			logger.error("ERROR: Failed to grab CVEs and CPEs from DB:\n{}", e.toString());
		}

		return affectedProducts;
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
	 * @param cve_id
	 *
	 * @return
	 */
	public int insertPatchSourceURL(String cve_id, String sourceURL) {
		try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(insertPatchSourceURLSql, Statement.RETURN_GENERATED_KEYS)) {
			pstmt.setString(1, cve_id);
			pstmt.setString(2, sourceURL);
			pstmt.executeUpdate();

			final ResultSet rs = pstmt.getGeneratedKeys();
			int generatedKey = 0;
			if (rs.next()) generatedKey = rs.getInt(1);
			else throw new SQLException("Could not retrieve key of newly created record, it may not have been inserted");

			logger.info("Inserted PatchURL: " + sourceURL);
			conn.close();
			return generatedKey;
		} catch (Exception e) {
			logger.error("ERROR: Failed to insert patch source with sourceURL {} for CVE ID {}\n{}", sourceURL,
					cve_id, e.getMessage());
			return -1;
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
	public void insertPatchCommit(int sourceId, String sourceURL, String commitId, java.util.Date commitDate, String commitMessage, String uniDiff) {

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(insertPatchCommitSql);) {

			pstmt.setInt(1, sourceId);
			pstmt.setString(2, sourceURL + "/commit/" + commitId);
			pstmt.setDate(3, new java.sql.Date(commitDate.getTime()));
			pstmt.setString(4, commitMessage);
			pstmt.setString(5, uniDiff);
			pstmt.executeUpdate();
		} catch (Exception e) {
			logger.error("ERROR: failed to insert patch commit from source {}\n{}", sourceURL, e);
		}
	}
}