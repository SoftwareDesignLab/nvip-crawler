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

import java.sql.*;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import model.cpe.AffectedProduct;
import model.cve.CompositeVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.pool.HikariPool.PoolInitializationException;

/**
 *
 * The DatabaseHelper class specific to the Product Name Extractor is
 * used to pull existing vulnerabilities, delete existing affected product data,
 * and insert new affected product data.
 *
 * @author Paul Vickers
 * @author Dylan Mulligan
 *
 */
public class DatabaseHelper {
	private HikariConfig config;
	private HikariDataSource dataSource;
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private final String selectVulnerabilitySql = "SELECT vulnerability.vuln_id, vulnerability.cve_id, description.description FROM vulnerability JOIN description ON vulnerability.description_id = description.description_id;";
	private final String selectSpecificVulnerabilitySql = "SELECT vulnerability.vuln_id, description.description FROM vulnerability JOIN description ON vulnerability.description_id = description.description_id WHERE vulnerability.cve_id = ?;";
	private final String insertAffectedProductSql = "INSERT INTO affectedproduct (cve_id, cpe, product_name, release_date, version, vendor, purl, swid_tag) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
	private final String deleteAffectedProductSql = "DELETE FROM affectedproduct where cve_id = ?;";

	/**
	 * Constructor for DatabaseHelper. Initializes the HikariDataSource connection to the database to be used.
	 */
	public DatabaseHelper(String databaseType, String hikariUrl, String hikariUser, String hikariPassword) {
		logger.info("New DatabaseHelper instantiated! It is configured to use " + databaseType + " database!");

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
	 * Creates and returns a HikariConfig object (to connect to the database).
	 *
	 * @param url database connection url
	 * @param user database username
	 * @param password database password
	 *
	 * @return HikariConfig object created using parameters
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
	 * Retrieves the connection from the DataSource (HikariCP).
	 * 
	 * @return the connection pooling connection
	 * @throws SQLException
	 */
	public Connection getConnection() throws SQLException {
		return dataSource.getConnection();
	}

	/**
	 * Insert affected products into the database. First deletes existing data
	 * in the database for the affected products in the list, then inserts the new data.
	 *
	 * @param affectedProducts list of affected products to be inserted
	 */
	public void insertAffectedProductsToDB(List<AffectedProduct> affectedProducts) {
		logger.info("Inserting Affected Products to DB!");

		// Delete existing affected product data for those in list
		deleteAffectedProducts(affectedProducts);

		// Insert affected products
		insertAffectedProducts(affectedProducts);
	}

	/**
	 * Updates the affected product table with a list of affected products.
	 *
	 * @param affectedProducts list of affected products
	 */
	public void insertAffectedProducts(List<AffectedProduct> affectedProducts) {
		logger.info("Inserting {} affected products...", affectedProducts.size());

		// CPE 2.3 Regex
		// Regex101: https://regex101.com/r/9uaTQb/1
		final Pattern cpePattern = Pattern.compile("cpe:2\\.3:[aho\\*\\-]:([^:]*):([^:]*):([^:]*):.*");

		int count = 0;
		try (Connection conn = getConnection();
				Statement stmt = conn.createStatement();
				PreparedStatement pstmt = conn.prepareStatement(insertAffectedProductSql);) {
			for (AffectedProduct affectedProduct : affectedProducts) {
				try {
					// Validate and extract CPE data
					final String cpe = affectedProduct.getCpe();
					final Matcher m = cpePattern.matcher(cpe);
					if(!m.find()){
						logger.warn("CPE in invalid format {}", cpe);
						continue;
					}

					pstmt.setString(1, affectedProduct.getCveId());
					pstmt.setString(2, affectedProduct.getCpe());
					pstmt.setString(3, affectedProduct.getProductName());
					pstmt.setString(4, affectedProduct.getReleaseDate());
					pstmt.setString(5, affectedProduct.getVersion());
					pstmt.setString(6, affectedProduct.getVendor());
					pstmt.setString(7, affectedProduct.getPURL());
					pstmt.setString(8, affectedProduct.getSWID());

					count += pstmt.executeUpdate();

				} catch (Exception e) {
					logger.error("Could not add affected release for Cve: {} Related Cpe: {}, Error: {}",
							affectedProduct.getCveId(), affectedProduct.getCpe(), e.toString());
				}
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		logger.info("Done. Inserted {} affected products into the database!", count);
	}

	/**
	 * Deletes affected products for given CVEs.
	 * 
	 * @param affectedProducts list of affected products to delete
	 */
	public void deleteAffectedProducts(List<AffectedProduct> affectedProducts) {
		logger.info("Deleting existing affected products in database for {} items..", affectedProducts.size());
		try (Connection conn = getConnection();
				Statement stmt = conn.createStatement();
				PreparedStatement pstmt = conn.prepareStatement(deleteAffectedProductSql);) {
			for (AffectedProduct affectedProduct : affectedProducts) {
				pstmt.setString(1, affectedProduct.getCveId());
				pstmt.executeUpdate();
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		logger.info("Done. Deleted existing affected products in database!");
	}

	/**
	 * Gets list of vulnerabilities from the database, formats them into CompositeVulnerability objects,
	 * and limits the returned list to maxVulnerabilities size.
	 *
	 * @param maxVulnerabilities max number of vulnerabilities to get
	 * @return list of fetched vulnerabilities
	 */
	public List<CompositeVulnerability> getAllCompositeVulnerabilities(int maxVulnerabilities) {
		ArrayList<CompositeVulnerability> vulnList = new ArrayList<>();
		synchronized (DatabaseHelper.class) {
			int vulnId;
			String cveId, description;
			try (Connection connection = getConnection()) {
				PreparedStatement pstmt = connection.prepareStatement(selectVulnerabilitySql);
				ResultSet rs = pstmt.executeQuery();

				int vulnCount = 0;
				// Iterate over result set until there are no results left or vulnCount >= maxVulnerabilities
				while (rs.next() && (maxVulnerabilities == 0 || vulnCount < maxVulnerabilities)) {
					vulnId = rs.getInt("vuln_id");
					cveId = rs.getString("cve_id");
					description = rs.getString("description");

					CompositeVulnerability vulnerability = new CompositeVulnerability(
							vulnId,
							cveId,
							description,
							CompositeVulnerability.CveReconcileStatus.UPDATE
					);
					vulnList.add(vulnerability);
					vulnCount++;
				}
				logger.info("Successfully loaded {} existing CVE items from DB!", vulnList.size());
			} catch (Exception e) {
				logger.error("Error while getting existing vulnerabilities from DB\nException: {}", e.getMessage());
				logger.error("This is a serious error! Product Name Extraction will not be able to proceed! Exiting...");
				System.exit(1);
			}
		}

		return vulnList;
	}

	/**
	 * Gets list of specific vulnerabilities by their CVE IDs from the database,
	 * formats them into CompositeVulnerability objects, and returns the list.
	 *
	 * @param cveIds list of CVEs to be pulled from database
	 * @return list of fetched vulnerabilities
	 */
	public List<CompositeVulnerability> getSpecificCompositeVulnerabilities(List<String> cveIds){
		ArrayList<CompositeVulnerability> vulnList = new ArrayList<>();
		synchronized (DatabaseHelper.class) {
			try (Connection connection = getConnection()) {

				// For each CVE ID in cveIds, query database for info specific to that cve
				for(String cveId : cveIds){
					PreparedStatement pstmt = connection.prepareStatement(selectSpecificVulnerabilitySql);
					pstmt.setString(1, cveId);

					ResultSet rs = pstmt.executeQuery();

					while (rs.next()) {
						int vulnId = rs.getInt("vuln_id");
						String description = rs.getString("description");

						CompositeVulnerability vulnerability = new CompositeVulnerability(
								vulnId,
								cveId,
								description,
								CompositeVulnerability.CveReconcileStatus.UPDATE
						);
						vulnList.add(vulnerability);
					}
				}
				logger.info("Successfully loaded {} existing CVE items from DB! {} CVE items were not found in the DB", vulnList.size(), cveIds.size() - vulnList.size());
			} catch (Exception e) {
				logger.error("Error while getting existing vulnerabilities from DB\nException: {}", e.getMessage());
				logger.error("This is a serious error! Product Name Extraction will not be able to proceed! Exiting...");
				System.exit(1);
			}
		}

		return vulnList;
	}

	// TODO: Move to API class
	public List<CompositeVulnerability> getVulnsByCpe(String cpe) {
		final String selectVulnerabilityByCpeSql =
		"SELECT vulnerability.vuln_id, vulnerability.cve_id, description.description, vulnerability.published_date, vulnerability.last_modified_date FROM nvip.vulnerability " +
		"JOIN nvip.description ON vulnerability.description_id = description.description_id " +
		"JOIN nvip.affectedproduct ON vulnerability.cve_id = affectedproduct.cve_id " +
		"WHERE affectedproduct.cve_id = ?";
		ArrayList<CompositeVulnerability> vulnList = new ArrayList<>();
		synchronized (DatabaseHelper.class) {
			try (Connection connection = getConnection()) {
				// Prepare SQL statement
				PreparedStatement pstmt = connection.prepareStatement(selectVulnerabilityByCpeSql);
				pstmt.setString(1, cpe);

				// Get result set and iterate
				ResultSet rs = pstmt.executeQuery();
				while (rs.next()) {
					// Extract values
					final int vulnId = rs.getInt(0);
					final String cveId = rs.getString(1);
					final String description = rs.getString(2);
					final String publishDate = rs.getString(3);
					final String lastModifiedDate = rs.getString(4);

					// Build vuln object
					CompositeVulnerability vulnerability = new CompositeVulnerability(
							vulnId,
							"",
							cveId,
							"",
							publishDate,
							lastModifiedDate,
							description,
							CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE
					);

					// Store object in output list
					vulnList.add(vulnerability);
				}
				logger.info("NVIP has loaded {} existing CVE items from DB!", vulnList.size());
			} catch (Exception e) {
				logger.error("Error while getting existing vulnerabilities from DB: {}", e.toString());
			}
		}

		// Return generated list of objects
		return vulnList;
	}

	/**
	 * Shut down connection pool.
	 */
	public void shutdown() {
		dataSource.close();
		config = null;
	}
}