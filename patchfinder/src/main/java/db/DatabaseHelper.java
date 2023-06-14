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

	private final String insertProductSql = "INSERT INTO affectedproduct (cve_id, cpe) VALUES (?, ?);";
	private final String getProductCountFromCpeSql = "SELECT count(*) from affectedproduct where cpe = ?";
	private final String getIdFromCpe = "SELECT * FROM affectedproduct where cpe = ?;";

	private final String insertAffectedReleaseSql = "INSERT INTO affectedproduct (cve_id, cpe, product_name, release_date, version, vendor, purl, swid_tag) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

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

	public Map<String, ArrayList<String>> getCPEsAndCVE() { // TODO
		return null;
	}

	public int getVulnIdByCveId(String cveId) { // TODO
		return 0;
	}

	public void insertPatchSourceURL(int vulnId, String commitUrl) { // TODO
	}

	// TODO
	public void insertPatchCommit(int vulnId, String commitUrl, String commitId, LocalDateTime commitDate, String commitMessage) {
	}
}