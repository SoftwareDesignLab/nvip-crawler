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

import java.sql.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import model.cpe.Product;
import model.cve.AffectedProduct;
import model.cve.CompositeVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.pool.HikariPool.PoolInitializationException;

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

	private final String insertProductSql = "INSERT INTO affectedproduct (cve_id, cpe) VALUES (?, ?);";
	private final String getProductCountFromCpeSql = "SELECT count(*) from affectedproduct where cpe = ?";
	private final String getIdFromCpe = "SELECT * FROM affectedproduct where cpe = ?;";

	private final String insertAffectedProductSql = "INSERT INTO affectedproduct (cve_id, cpe, product_name, release_date, version, vendor, purl, swid_tag) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

	private static DatabaseHelper databaseHelper = null;
	private static Map<String, CompositeVulnerability> existingCompositeVulnMap = new HashMap<>();

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
	 * The private constructor sets up HikariCP for connection pooling. Singleton
	 * DP!
	 */
	private DatabaseHelper() {
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
	 * Store affected products in DB
	 * @param vulnList
	 */
	public void insertAffectedProductsToDB(List<CompositeVulnerability> vulnList) {

		// get all identified affected releases
		List<AffectedProduct> listAllAffectedProducts = new ArrayList<>();
		for (CompositeVulnerability vulnerability : vulnList) {
			if (vulnerability.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE)
				continue; // skip the ones that are not changed!
			listAllAffectedProducts.addAll(vulnerability.getAffectedProducts());
		}

		logger.info("Inserting Affected Products to DB!");
		// delete existing affected release info in db ( for CVEs in the list)
		databaseHelper.deleteAffectedProducts(listAllAffectedProducts);

		// now insert affected releases (referenced products are already in db)
		databaseHelper.insertAffectedProductsV2(listAllAffectedProducts);

		// TODO: Should be in program driver, probably PNEController
//		// prepare CVE summary table for Web UI

//		logger.info("Preparing CVE summary table for Web UI...");
//		PrepareDataForWebUi cveDataForWebUi = new PrepareDataForWebUi();
//		cveDataForWebUi.prepareDataforWebUi();

		databaseHelper.shutdown();
	}

	/**
	 * Gets a product ID from database based on CPE
	 *
	 * @param cpe CPE string of product
	 * @return product ID if product exists in database, -1 otherwise
	 */
	public int getProdIdFromCpe(String cpe) {
		int result;
		try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(getIdFromCpe);) {
			pstmt.setString(1, cpe);
			ResultSet res = pstmt.executeQuery();
			if (res.next())
				result = res.getInt("product_id");
			else
				result = -1;
		} catch (SQLException e) {
			logger.error(e.getMessage());
			result = -2;
		}
		return result;
	}

	/**
	 * Updates the affected release table with a list of affected releases
	 * 
	 * @param affectedProducts list of affected release objects
	 */
	public void insertAffectedProductsV2(List<AffectedProduct> affectedProducts) {
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
					String productName = "UNKNOWN";
					if(!m.find()) logger.warn("CPE in invalid format {}", cpe);
					else productName = m.group(2);

					pstmt.setString(1, affectedProduct.getCveId());
					pstmt.setString(2, cpe);
					pstmt.setString(3, productName);
					pstmt.setString(4, affectedProduct.getReleaseDate());
					pstmt.setString(5, affectedProduct.getVersion());
					pstmt.setString(6, affectedProduct.getVendor());
					pstmt.setString(7, affectedProduct.getPURL(productName));
					pstmt.setString(8, affectedProduct.getSWID(productName));

					count += pstmt.executeUpdate();
//					logger.info("Added {} as an affected release for {}", prodId, affectedProduct.getCveId());
				} catch (Exception e) {
					logger.error("Could not add affected release for Cve: {} Related Cpe: {}, Error: {}",
							affectedProduct.getCveId(), affectedProduct.getCpe(), e.toString());
					//e.printStackTrace();
				}
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		logger.info("Done. Inserted {} affected products into the database!", count);
	}

	/**
	 * Deletes affected releases for given CVEs
	 * 
	 * @param affectedProducts list of releases to delete
	 */
	public void deleteAffectedProducts(List<AffectedProduct> affectedProducts) {
		logger.info("Deleting existing affected products in database for {} items..", affectedProducts.size());
		String deleteAffectedProductSql = "DELETE FROM affectedproduct where cve_id = ?;";
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
	 * Gets list of vulnerabilities from the database, formatting them into CompositeVulnerability objects,
	 * and limiting the return to maxVulnerabilities size.
	 *
	 * @param maxVulnerabilities max number of vulnerabilities to get
	 * @return a map of fetched vulnerabilities
	 */
	public Map<String, CompositeVulnerability> getExistingCompositeVulnerabilities(int maxVulnerabilities) {
		if (existingCompositeVulnMap.size() == 0) {
		synchronized (DatabaseHelper.class) {
			if (existingCompositeVulnMap.size() == 0) {
				int vulnId;
				String cveId, description;
				existingCompositeVulnMap = new HashMap<>();
				try (Connection connection = getConnection();) {

					String selectSql = "SELECT vulnerability.vuln_id, vulnerability.cve_id, description.description FROM nvip.vulnerability JOIN nvip.description ON vulnerability.description_id = description.description_id";
					PreparedStatement pstmt = connection.prepareStatement(selectSql);
					ResultSet rs = pstmt.executeQuery();

					int vulnCount = 0;
					// Iterate over result set until there are no results left or vulnCount >= maxVulnerabilities
					while (rs.next() && (maxVulnerabilities == 0 || vulnCount < maxVulnerabilities)) {
						vulnId = rs.getInt("vuln_id");
						cveId = rs.getString("cve_id");
						description = rs.getString("description");

						CompositeVulnerability existingVulnInfo = new CompositeVulnerability(
								vulnId,
								cveId,
								description,
								CompositeVulnerability.CveReconcileStatus.UPDATE
						);
						existingCompositeVulnMap.put(cveId, existingVulnInfo);
						vulnCount++;
					}
					logger.info("NVIP has loaded {} existing CVE items from DB!", existingCompositeVulnMap.size());
				} catch (Exception e) {
					logger.error("Error while getting existing vulnerabilities from DB\nException: {}", e.getMessage());
					logger.error(
							"This is a serious error! NVIP will not be able to decide whether to insert or update! Exiting...");
					System.exit(1);
				}
			}
		}
	} else {
		logger.warn("NVIP has loaded {} existing CVE items from memory!", existingCompositeVulnMap.size());
	}

		return existingCompositeVulnMap;
	}

	/**
	 * Shut down connection pool.
	 */
	public void shutdown() {
		dataSource.close();
		config = null;
	}
}