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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.URI;
import java.sql.*;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.pool.HikariPool.PoolInitializationException;

import model.*;
import utils.*;

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

	// TODO: Fix insertProductSql.domain? "INSERT INTO affectedproduct (CPE, domain) VALUES (?, ?);";
	private final String insertProductSql = "INSERT INTO affectedproduct (CPE) VALUES (?);";
	private final String getProductCountFromCpeSql = "SELECT count(*) from affectedproduct where cpe = ?";
	private final String getIdFromCpe = "SELECT * FROM affectedproduct where cpe = ?;";

	private final String insertAffectedReleaseSql = "INSERT INTO affectedproduct (cve_id, release_date, version) VALUES (?, ?, ?);";

	private static DatabaseHelper databaseHelper = null;
	private static Map<String, Vulnerability> existingVulnMap = new HashMap<>();
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
		try {
			MyProperties propertiesNvip = new MyProperties();
			propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
			databaseType = propertiesNvip.getDatabaseType();
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

	/**
	 * used to insert a list of CPE products into the database
	 *
	 * @param products List of product objects
	 * @return Number of inserted products, <0 if error.
	 */
	public int insertCpeProducts(Collection<Product> products) {
		try (Connection conn = getConnection();
				PreparedStatement pstmt = conn.prepareStatement(insertProductSql);
				PreparedStatement getCount = conn.prepareStatement(getProductCountFromCpeSql);) {
			int count = 0;
			int total = products.size();
			for (Product product : products) {
				getCount.setString(1, product.getCpe());
				ResultSet res = getCount.executeQuery();
				if (res.next() && res.getInt(1) != 0) {
					continue; // product already exists, skip!
				}
				pstmt.setString(1, product.getCpe());
				// TODO: Fix insertProductSql
//				pstmt.setString(2, product.getDomain());
				pstmt.executeUpdate();
				count++;
			}

			logger.info(
					"\rInserted: " + count + " of " + total + " products to DB! Skipped: " + (total - count) + " existing ones!");
			return count;
		} catch (SQLException e) {
			logger.error(e.getMessage());
			return -1;
		}
	}

	/**
	 * gets a product ID from database based on CPE
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
	 * updates the affected release table with a list of affected releases
	 * 
	 * @param affectedReleases list of affected release objects
	 */
	public void insertAffectedReleasesV2(List<AffectedRelease> affectedReleases) {
		logger.info("Inserting {} affected releases...", affectedReleases.size());
		int count = 0;
		try (Connection conn = getConnection();
				Statement stmt = conn.createStatement();
				PreparedStatement pstmt = conn.prepareStatement(insertAffectedReleaseSql);) {
			for (AffectedRelease affectedRelease : affectedReleases) {
				try {
					int prodId = getProdIdFromCpe(affectedRelease.getCpe());
					pstmt.setString(1, affectedRelease.getCveId());
					pstmt.setInt(2, prodId);
					pstmt.setString(3, affectedRelease.getReleaseDate());
					pstmt.setString(4, affectedRelease.getVersion());
					count += pstmt.executeUpdate();
//					logger.info("Added {} as an affected release for {}", prodId, affectedRelease.getCveId());
				} catch (Exception e) {
					logger.error("Could not add affected release for Cve: {} Related Cpe: {}, Error: {}",
							affectedRelease.getCveId(), affectedRelease.getCpe(), e.toString());
					//e.printStackTrace();
				}
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		logger.info("Done. Inserted {} affected releases into the database!", count);
	}

	/**
	 * delete affected releases for given CVEs
	 * 
	 * @param affectedReleases
	 */
	public void deleteAffectedReleases(List<AffectedRelease> affectedReleases) {
		logger.info("Deleting existing affected releases in database for {} items..", affectedReleases.size());
		String deleteAffectedReleaseSql = "DELETE FROM affectedproduct where cve_id = ?;";
		try (Connection conn = getConnection();
				Statement stmt = conn.createStatement();
				PreparedStatement pstmt = conn.prepareStatement(deleteAffectedReleaseSql);) {
			for (AffectedRelease affectedRelease : affectedReleases) {
				pstmt.setString(1, affectedRelease.getCveId());
				pstmt.executeUpdate();
			}
		} catch (SQLException e) {
			logger.error(e.toString());
		}
		logger.info("Done. Deleted existing affected releases in database!");
	}

	public Map<String, CompositeVulnerability> getExistingCompositeVulnerabilities() {

		if (existingCompositeVulnMap.size() == 0) {
		synchronized (DatabaseHelper.class) {
			if (existingCompositeVulnMap.size() == 0) {
				int vulnId;
				String cveId, description, published_date, last_modified_date, srcUrl, platform, srcDomain = "";
				int existAtNvd, existAtMitre;
				existingCompositeVulnMap = new HashMap<>();
				try (Connection connection = getConnection();) {

					String selectSql = """
								SELECT vulnerability.vuln_id, vulnerability.cve_id, description.description, vulnerability.published_date, vulnerability.last_modified_date
								FROM nvip.vulnerability
								JOIN nvip.description ON vulnerability.description_id = description.description_id
								""";
					PreparedStatement pstmt = connection.prepareStatement(selectSql);
					ResultSet rs = pstmt.executeQuery();

					while (rs.next()) {
						vulnId = rs.getInt("vuln_id");
						cveId = rs.getString("cve_id");
						description = rs.getString("description");
						published_date = rs.getString("published_date");
						last_modified_date = rs.getString("last_modified_date");

						// TODO: Fix these
						existAtNvd = 0; /* rs.getInt("exists_at_nvd"); */
						existAtMitre = 0; /* rs.getInt("exists_at_mitre"); */
						platform = "";
						srcUrl = ""; /* rs.getString("source_url"); */

						try { srcDomain = new URI(srcUrl).getHost(); }
						catch (Exception e) { logger.error("Error thrown while parsing URL", e); }
						CompositeVulnerability existingVulnInfo = new CompositeVulnerability(
								vulnId,
								srcUrl,
								cveId,
								platform,
								published_date,
								last_modified_date,
								description,
								srcDomain,
								existAtNvd,
								existAtMitre
						);
						existingCompositeVulnMap.put(cveId, existingVulnInfo);
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

						String selectSql = """
								SELECT vulnerability.vuln_id, vulnerability.cve_id, description.description, vulnerability.created_date
								FROM nvip.vulnerability
								JOIN nvip.description ON vulnerability.description_id = description.description_id
								""";
						PreparedStatement pstmt = connection.prepareStatement(selectSql);
						ResultSet rs = pstmt.executeQuery();

						while (rs.next()) {
							vulnId = rs.getInt("vuln_id");
							cveId = rs.getString("cve_id");
							description = rs.getString("description");
							createdDate = rs.getString("created_date");
							existAtNvd = 0; /* rs.getInt("exists_at_nvd"); */
							existAtMitre = 0; /* rs.getInt("exists_at_mitre"); */
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
	 * shut down connection pool. U
	 */
	public void shutdown() {
		dataSource.close();
		config = null;
	}


}