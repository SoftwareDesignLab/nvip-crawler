package db;

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

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.pool.HikariPool.PoolInitializationException;
import model.CpeEntry;
import model.CpeGroup;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The DatabaseHelper class is used to facilitate database interactions for the Patchfinder
 *
 * @author Dylan Mulligan
 */
public class DatabaseHelper {
	private HikariConfig config = null;
	private HikariDataSource dataSource;
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	private final String selectAffectedProductsSql = "SELECT cve_id, cpe FROM affectedproduct GROUP BY product_name, affected_product_id ORDER BY cve_id DESC, version ASC;";
	private final String selectAffectedProductsByIdsSql = "SELECT cve_id, cpe FROM affectedproduct WHERE cve_id = ? GROUP BY product_name, affected_product_id ORDER BY cve_id DESC, version ASC;";
	private final String getExistingSourceUrlsSql = "SELECT source_url, source_url_id FROM patchsourceurl";
	private final String getExistingPatchCommitsSql = "SELECT commit_sha FROM patchcommit";
	private final String insertPatchSourceURLSql = "INSERT INTO patchsourceurl (cve_id, source_url) VALUES (?, ?);";
	private final String insertPatchCommitSql = "INSERT INTO patchcommit (source_url_id, cve_id, commit_sha, commit_date, commit_message, uni_diff, timeline, time_to_patch, lines_changed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
	// Regex101: https://regex101.com/r/9uaTQb/1
	private final String deletePatchCommitSql = "DELETE FROM patchcommit WHERE commit_sha = ?;";
	private final String getCveSourcesSql = "SELECT cve_id, source_url FROM nvip.rawdescription WHERE source_url != \"\";";
	private final String getCveSourcesNVDSql = "SELECT cve_id, source_url FROM nvip.nvdsourceurl WHERE cve_id = ?;";
	private final String insertFixSourceURLSql = "INSERT INTO fixes (cve_id, source_url) VALUES (?, ?);";
	private final String getExistingFixSourceUrlsSql = "SELECT source_url FROM fixes;";
	private final String insertFixSql = "INSERT INTO fixes (fix_id, cve_id, fix_description, source_url_id) VALUES (?, ?, ?, ?);";
	public static final Pattern CPE_PATTERN = Pattern.compile("cpe:2\\.3:[aho\\*\\-]:([^:]*):([^:]*):([^:]*):.*");

	/**
	 * Creates a DBH instance given db type, url, username, and password. These values are used to create a config
	 * for Hikari and load it.
	 *
	 * @param databaseType database type identifier (mysql, postgres, etc.)
	 * @param hikariUrl url to connect to the database
	 * @param hikariUser database username
	 * @param hikariPassword database password
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
			logger.info("Attempting to create HIKARI config from provided values");
			config = createHikariConfig(hikariUrl, hikariUser, hikariPassword);
		}

		try {
			if(config == null) throw new IllegalArgumentException("Failed to create HIKARI config");
			dataSource = new HikariDataSource(config); // init data source
		} catch (PoolInitializationException e2) {
			logger.error("Error initializing data source! Check the value of the database user/password in the environment variables! Current values are: {}", config != null ? config.getDataSourceProperties() : null);
			System.exit(1);

		}
	}

	/**
	 * Creates a HikariConfig object from the given values.
	 *
	 * @param url url to connect to the database
	 * @param user database username
	 * @param password database password
	 * @return created HikariConfig object
	 */
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

		} else {
			hikariConfig = null;
		}

		return hikariConfig;
	}

	/**
	 * Retrieves the connection from the DataSource (HikariCP)
	 * 
	 * @return the connection pooling connection
	 * @throws SQLException if a SQL error occurs
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

	//
	// PATCHES
	//

	/**
	 * Deletes a patchcommit from the database given a commit SHA
	 * @param commitSha the commit SHA to delete
	 */
	public void deletePatchCommit(String commitSha) {
		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(deletePatchCommitSql)) {
			pstmt.setString(1, commitSha);
			pstmt.executeUpdate();
		} catch (Exception e) {
			logger.error(e.toString());
		}
	}

	/**
	 * Gets a map of CVEs -> existing source urls from the database
	 * @return a map of CVEs -> existing source urls
	 */
	public Map<String, Integer> getExistingSourceUrls() {
		final Map<String, Integer> urls = new HashMap<>();

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(getExistingSourceUrlsSql)) {
			ResultSet rs = pstmt.executeQuery();
			while(rs.next()) { urls.put(rs.getString(1), rs.getInt(2)); }
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return urls;
	}

	/**
	 * Gets a set of existing patch commit SHAs from the database
	 * @return a set of existing patch commit SHAs
	 */
	public Set<String> getExistingPatchCommitShas() {
		final Set<String> urls = new HashSet<>();

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(getExistingPatchCommitsSql)) {
			ResultSet rs = pstmt.executeQuery();
			while(rs.next()) { urls.add(rs.getString(1)); }
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return urls;
	}

	/**
	 * Collects a map of CPEs with their correlated CVE and Vuln ID used for
	 * collecting patches given a list of CVE ids.
	 *
	 * @param cveIds CVEs to get affected products for
	 * @return a map of affected products
	 */
	public Map<String, CpeGroup> getAffectedProducts(List<String> cveIds) {
		Map<String, CpeGroup> affectedProducts = new HashMap<>();
		// Prepare statement
		try (Connection conn = getConnection();
			 PreparedStatement getAll = conn.prepareStatement(selectAffectedProductsSql);
			 PreparedStatement getById = conn.prepareStatement(selectAffectedProductsByIdsSql)
		) {
			// Execute correct statement and get result set
			ResultSet res = null;
			if(cveIds == null) {
				res = getAll.executeQuery();
				parseAffectedProducts(affectedProducts, res);
			}
			else {
				for (String cveId : cveIds) {
					getById.setString(1, cveId);
					res = getById.executeQuery();
					parseAffectedProducts(affectedProducts, res);
				}
			}

		} catch (Exception e) {
			logger.error("ERROR: Failed to generate affected products map: {}", e.toString());
		}

		return affectedProducts;
	}

	/**
	 * Parses affected product data from the ResultSet into CpeGroup objects in the affectedProducts map.
	 *
	 * @param affectedProducts output map of CVE ids -> products
	 * @param res result set from database query
	 * @throws SQLException if a SQL error occurs
	 */
	private void parseAffectedProducts(Map<String, CpeGroup> affectedProducts, ResultSet res) throws SQLException {
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
	}

	/**
	 * Inserts given source URL into the patch source table
	 *
	 * @param existingSourceUrls map of CVE ids -> the id of the source url
	 * @param cve_id CVE being processed
	 * @param sourceURL source url to insert
	 * @return generated primary key (or existing key)
	 */
	public int insertPatchSourceURL(Map<String, Integer> existingSourceUrls, String cve_id, String sourceURL) {
		// Check if source already exists
		if(existingSourceUrls.containsKey(sourceURL)) {
			// Get and return id from map
			return existingSourceUrls.get(sourceURL);
		} else { // Otherwise, insert and return generated id
			try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(insertPatchSourceURLSql, Statement.RETURN_GENERATED_KEYS)) {
				pstmt.setString(1, cve_id);
				pstmt.setString(2, sourceURL);
				pstmt.executeUpdate();

				final ResultSet rs = pstmt.getGeneratedKeys();
				int generatedKey = 0;
				if (rs.next()) generatedKey = rs.getInt(1);
				else throw new SQLException("Could not retrieve key of newly created record, it may not have been inserted");

				conn.close();
				logger.info("Inserted PatchURL: " + sourceURL);
				existingSourceUrls.put(sourceURL, generatedKey);
				return generatedKey;
			} catch (Exception e) {
				logger.error("ERROR: Failed to insert patch source with sourceURL {} for CVE ID {}\n{}", sourceURL,
						cve_id, e.getMessage());
				return -1;
			}
		}
	}

	/**
	 * Method for inserting a patch commit into the patchcommit table
	 *
	 * @param sourceId id of the source url
	 * @param commitSha commit SHA
	 * @param commitDate commit date
	 * @param commitMessage commit message
	 * @param uniDiff unified diff String
	 * @param timeLine timeline list of String objects
	 * @param timeToPatch time from CVE release -> patch release
	 * @param linesChanged number of lines changed
	 * @throws IllegalArgumentException if given source id is invalid (sourceId < 0)
	 */
	public void insertPatchCommit(int sourceId, String cveId, String commitSha, java.util.Date commitDate, String commitMessage, String uniDiff, List<String> timeLine, String timeToPatch, int linesChanged) throws IllegalArgumentException {
		if (sourceId < 0) throw new IllegalArgumentException("Invalid source id provided, ensure id is non-negative");

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(insertPatchCommitSql);
			 PreparedStatement pstmtExistingCommit = connection.prepareStatement("SELECT commit_sha FROM patchcommit WHERE commit_sha = ? LIMIT 1");
			 PreparedStatement pstmtUpdateCommit = connection.prepareStatement("UPDATE patchcommit SET commit_date = ?, commit_message = ?, uni_diff = ?, timeline = ?, time_to_patch = ?, lines_changed = ? WHERE commit_sha = ?")
		) {
			// Check if the commit URL already exists in the database
			pstmtExistingCommit.setString(1, commitSha);
			ResultSet existingCommitResult = pstmtExistingCommit.executeQuery();

			if (existingCommitResult.next()) {
				// Existing commit found
				logger.warn("Patch commit '{}' already exists in the database", commitSha);

				// Perform the appropriate action for existing entries (diff, replace, ignore)
				// Here, we are updating the existing commit with the new information
				pstmtUpdateCommit.setDate(1, new java.sql.Date(commitDate.getTime()));
				pstmtUpdateCommit.setString(2, commitMessage);// TODO: Fix data truncation error
				pstmtUpdateCommit.setString(3, uniDiff);
				pstmtUpdateCommit.setString(4, timeLine.toString());
				pstmtUpdateCommit.setString(5, timeToPatch);
				pstmtUpdateCommit.setInt(6, linesChanged);
				pstmtUpdateCommit.setString(7, commitSha);
				pstmtUpdateCommit.executeUpdate();

				logger.info("Existing patch commit updated: {}", commitSha);
			} else {
				// Insert the new patch commit
				pstmt.setInt(1, sourceId);
				pstmt.setString(2, cveId);
				pstmt.setString(3, commitSha);
				pstmt.setDate(4, new java.sql.Date(commitDate.getTime()));
				pstmt.setString(5, commitMessage);
				pstmt.setString(6, uniDiff);
				pstmt.setString(7, timeLine.toString());
				pstmt.setString(8, timeToPatch);
				pstmt.setInt(9, linesChanged);
				pstmt.executeUpdate();

				logger.info("New patch commit inserted: {}", commitSha);
			}
		} catch (Exception e) {
			logger.error("ERROR: Failed to insert/update patch commit from source {}: {}", commitSha, e);
			throw new IllegalArgumentException(e);
		}
	}

	public ArrayList<String> getCveSources(String cve_id) {
		ArrayList<String> sources = new ArrayList<>();
		try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(getCveSourcesSql)) {
			pstmt.setString(1, cve_id);
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				sources.add(rs.getString("source"));
			}
		} catch (Exception e) {
			logger.error("ERROR: Failed to get CVE sources for CVE ID {}\n{}", cve_id, e.getMessage());
		}
		return sources;
	}

	//
	// Fixes
	//

	/**
	 * Gets a map of CVEs -> existing fix source urls from the database
	 * @return a map of CVEs -> existing fix source urls
	 */
	public Map<String, Integer> getExistingFixSourceUrls() {
		final Map<String, Integer> urls = new HashMap<>();

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(getExistingFixSourceUrlsSql)) {
			ResultSet rs = pstmt.executeQuery();
			while(rs.next()) { urls.put(rs.getString(1), rs.getInt(2)); }
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return urls;
	}

	// TODO: Do we need fix equivalents of these methods?
//	/**
//	 * Deletes a patchcommit from the database given a commit SHA
//	 * @param commitSha the commit SHA to delete
//	 */
//	public void deletePatchCommit(String commitSha) {
//		try (Connection connection = getConnection();
//			 PreparedStatement pstmt = connection.prepareStatement(deletePatchCommitSql)) {
//			pstmt.setString(1, commitSha);
//			pstmt.executeUpdate();
//		} catch (Exception e) {
//			logger.error(e.toString());
//		}
//	}
//
//	/**
//	 * Gets a map of CVEs -> existing source urls from the database
//	 * @return a map of CVEs -> existing source urls
//	 */
//	public Map<String, Integer> getExistingSourceUrls() {
//		final Map<String, Integer> urls = new HashMap<>();
//
//		try (Connection connection = getConnection();
//			 PreparedStatement pstmt = connection.prepareStatement(getExistingSourceUrlsSql)) {
//			ResultSet rs = pstmt.executeQuery();
//			while(rs.next()) { urls.put(rs.getString(1), rs.getInt(2)); }
//		} catch (Exception e) {
//			logger.error(e.toString());
//		}
//
//		return urls;
//	}
//
//	/**
//	 * Gets a set of existing patch commit SHAs from the database
//	 * @return a set of existing patch commit SHAs
//	 */
//	public Set<String> getExistingPatchCommitShas() {
//		final Set<String> urls = new HashSet<>();
//
//		try (Connection connection = getConnection();
//			 PreparedStatement pstmt = connection.prepareStatement(getExistingPatchCommitsSql)) {
//			ResultSet rs = pstmt.executeQuery();
//			while(rs.next()) { urls.add(rs.getString(1)); }
//		} catch (Exception e) {
//			logger.error(e.toString());
//		}
//
//		return urls;
//	}
//
//	/**
//	 * Collects a map of CPEs with their correlated CVE and Vuln ID used for
//	 * collecting patches given a list of CVE ids.
//	 *
//	 * @param cveIds CVEs to get affected products for
//	 * @return a map of affected products
//	 */
//	public Map<String, CpeGroup> getAffectedProducts(List<String> cveIds) {
//		Map<String, CpeGroup> affectedProducts = new HashMap<>();
//		// Prepare statement
//		try (Connection conn = getConnection();
//			 PreparedStatement getAll = conn.prepareStatement(selectAffectedProductsSql);
//			 PreparedStatement getById = conn.prepareStatement(selectAffectedProductsByIdsSql)
//		) {
//			// Execute correct statement and get result set
//			ResultSet res = null;
//			if(cveIds == null) {
//				res = getAll.executeQuery();
//				parseAffectedProducts(affectedProducts, res);
//			}
//			else {
//				for (String cveId : cveIds) {
//					getById.setString(1, cveId);
//					res = getById.executeQuery();
//					parseAffectedProducts(affectedProducts, res);
//				}
//			}
//
//		} catch (Exception e) {
//			logger.error("ERROR: Failed to generate affected products map: {}", e.toString());
//		}
//
//		return affectedProducts;
//	}
//
//	/**
//	 * Parses affected product data from the ResultSet into CpeGroup objects in the affectedProducts map.
//	 *
//	 * @param affectedProducts output map of CVE ids -> products
//	 * @param res result set from database query
//	 * @throws SQLException if a SQL error occurs
//	 */
//	private void parseAffectedProducts(Map<String, CpeGroup> affectedProducts, ResultSet res) throws SQLException {
//		// Parse results
//		while (res.next()) {
//			// Extract cveId and cpe from result
//			final String cveId = res.getString("cve_id");
//			final String cpe = res.getString("cpe");
//
//			// Extract product name and version from cpe
//			final Matcher m = CPE_PATTERN.matcher(cpe);
//			if(!m.find()) {
//				logger.warn("Invalid cpe '{}' could not be parsed, skipping product", cpe);
//				continue;
//			}
//			final String vendor = m.group(1);
//			final String name = m.group(2);
//			final String version = m.group(3);
//			final CpeEntry entry = new CpeEntry(name, version, cpe);
//
//			// If we already have this cveId stored, add specific version
//			if (affectedProducts.containsKey(cveId)) {
//				affectedProducts.get(cveId).addVersion(entry);
//			} else {
//				final CpeGroup group = new CpeGroup(vendor, name);
//				group.addVersion(entry);
//				affectedProducts.put(cveId, group);
//			}
//		}
//	}

	/**
	 * Inserts given source URL into the fix source table
	 *
	 * @param existingSourceUrls map of CVE ids -> the id of the source url
	 * @param cve_id CVE being processed
	 * @param sourceURL source url to insert
	 * @return generated primary key (or existing key)
	 */
	public int insertFixSourceURL(Map<String, Integer> existingSourceUrls, String cve_id, String sourceURL) {
		// Check if source already exists
		if(existingSourceUrls.containsKey(sourceURL)) {
			// Get and return id from map
			return existingSourceUrls.get(sourceURL);
		} else { // Otherwise, insert and return generated id
			try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(insertFixSourceURLSql, Statement.RETURN_GENERATED_KEYS)) {
				pstmt.setString(1, cve_id);
				pstmt.setString(2, sourceURL);
				pstmt.executeUpdate();

				final ResultSet rs = pstmt.getGeneratedKeys();
				int generatedKey = 0;
				if (rs.next()) generatedKey = rs.getInt(1);
				else throw new SQLException("Could not retrieve key of newly created record, it may not have been inserted");

				conn.close();
				logger.info("Inserted FixURL: " + sourceURL);
				existingSourceUrls.put(sourceURL, generatedKey);
				return generatedKey;
			} catch (Exception e) {
				logger.error("ERROR: Failed to insert fix source with URL {} for CVE ID {}\n{}", sourceURL,
						cve_id, e.getMessage());
				return -1;
			}
		}
	}

	// TODO: Implement
	/**
	 * Method for inserting a fix into the fixes table
	 * Should also check for duplicates
	 * @param fix_id id of the fix
	 * @param cve_id CVE being processed
	 * @param fix_description description of the fix
	 * @param source_url_id id of the source url
	 * @throws IllegalArgumentException if given source id is invalid (sourceId < 0)
	 */
	public void insertFix(int fix_id, int cve_id, String fix_description, int source_url_id) throws IllegalArgumentException, SQLException {
		if (source_url_id < 0) throw new IllegalArgumentException("Invalid source id provided, ensure id is non-negative");

		try (Connection connection = getConnection();
			 PreparedStatement pstmt = connection.prepareStatement(insertFixSql);
			 PreparedStatement pstmtExistingCommit = connection.prepareStatement("SELECT fix_id FROM fixes WHERE fix_id = ? LIMIT 1");
			 PreparedStatement pstmtUpdateFix = connection.prepareStatement("SELECT fix_id FROM fixes WHERE fix_id = ? AND fix_description = ? LIMIT 1");
		) {
			// Check if the fix already exists
			pstmtExistingCommit.setInt(1, cve_id);
			ResultSet rs = pstmtExistingCommit.executeQuery();
			if (rs.next()) {
				logger.info("Fix already exists for CVE ID {}", cve_id);
				//updateFix(fix_id, cve_id, fix_description, source_url_id);
				pstmtUpdateFix.setInt(1, fix_id);
				pstmtUpdateFix.setString(2, fix_description);
				rs = pstmtUpdateFix.executeQuery();
			} else {
				// Insert the fix
				pstmt.setInt(1, fix_id);
				pstmt.setInt(2, cve_id);
				pstmt.setString(3, fix_description);
				pstmt.setInt(4, source_url_id);
				pstmt.executeUpdate();
				logger.info("Inserted fix for CVE ID {}", cve_id);
			}
		}



	}

	/**
	 * Method for getting the source url from nvddata
	 *
	 * @param cve_id CVE being processed
	 * @return source url
	 */
	public ArrayList<String> getCveSourcesNVD(String cve_id) {
		ArrayList<String> sourceURL = new ArrayList<>();
		try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(getCveSourcesNVDSql)) {
			pstmt.setString(1, cve_id);
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				sourceURL.add(rs.getString("source_url"));
			}
		} catch (Exception e) {
			logger.error("ERROR: Failed to get source URL for CVE ID {}\n{}", cve_id, e.getMessage());
		}
		return sourceURL;
	}
}