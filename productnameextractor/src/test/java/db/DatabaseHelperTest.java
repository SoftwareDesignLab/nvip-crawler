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

import com.zaxxer.hikari.HikariDataSource;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.cpe.AffectedProduct;
import edu.rit.se.nvip.model.cve.CompositeVulnerability;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.*;
import java.util.*;


import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Collection of tests for the DatabaseHelper class. The general approach here it to use mocking/spying in order to
 * sever dependenies on database connections. Generally, SQL arguments are verified, execute commands are verified, and
 * return values are verified where applicable.
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class DatabaseHelperTest {
	protected static String databaseType = "mysql";
	protected static String hikariUrl = "jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true";
	protected static String hikariUser = "root";
	protected static String hikariPassword = "root";
	private DatabaseHelper dbh;
	@Mock
	private HikariDataSource hds;
	@Mock
	private Connection conn;
	@Mock
	private PreparedStatement pstmt;
	@Mock
	private ResultSet res;

	private void setMocking() {
		try {
			when(hds.getConnection()).thenReturn(conn);
			when(conn.prepareStatement(any())).thenReturn(pstmt);
			when(pstmt.executeQuery()).thenReturn(res);
			when(conn.createStatement()).thenReturn(pstmt);
		} catch (SQLException ignored) {}
	}

	/**
	 * Sets up the "database" results to return n rows
	 * @param n Number of rows (number of times next() will return true)
	 */
	private void setResNextCount(int n) {
		try {
			when(res.next()).thenAnswer(new Answer<Boolean>() {
				private int iterations = n;
				public Boolean answer(InvocationOnMock invocation) {
					return iterations-- > 0;
				}
			});
		} catch (SQLException ignored) {}
	}

	private List<AffectedProduct> buildDummyProducts(int count) {
		List<AffectedProduct> products = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			String cpeName = "cpe:2.3:a:" + i + ":" + i + ":*:*:*:*:*:*:*:*";
			products.add(new AffectedProduct(i, "cve"+i, cpeName, "productName"+i, "date"+i, "version"+i, "vendor"+i));
		}
		return products;
	}

	@Before
	public void setUp() {
		this.dbh = new DatabaseHelper(databaseType, hikariUrl, hikariUser, hikariPassword);
		ReflectionTestUtils.setField(this.dbh, "dataSource", this.hds);
		this.setMocking();
	}

	@Test
	public void getConnectionTest() {
		try {
			Connection conn = dbh.getConnection();
			assertNotNull(conn);
		} catch (SQLException ignored) {
		}
	}

	@Test
	public void getProdIdFromCpeTest() {
		int outId = 1337;
		String cpe = "cpe";

		try {
			setResNextCount(1);
			when(res.getInt("product_id")).thenReturn(outId);
			int prodId = dbh.getProdIdFromCpe(cpe);
			verify(pstmt).setString(1, cpe);
			assertEquals(outId, prodId);

			setResNextCount(0);
			assertEquals(-1, dbh.getProdIdFromCpe(cpe));
		} catch (SQLException ignored) {}
	}

	/**
	 * Tests the insertAffectedProducts method. In this case since there are 5 products,
	 * there should be 8 psmt.setStrings() so 8x5=40
	 * @throws SQLException
	 */
	@Test
	public void insertAffectedProductsTest() {
		int inCount = 5;
		List<AffectedProduct> products = buildDummyProducts(inCount);
		dbh.insertAffectedProducts(products);
		try {
			verify(pstmt, times(inCount*8)).setString(anyInt(), any());
			verify(pstmt, times(inCount)).executeUpdate();
			verify(pstmt).setString(1, products.get(inCount-1).getCveId());
		} catch (SQLException ignored) {}
	}

	@Test
	public void deleteAffectedProductsTest() {
		int count = 5;
		List<AffectedProduct> products = buildDummyProducts(count);
		dbh.deleteAffectedProducts(products);
		try {
			verify(pstmt, times(count)).setString(anyInt(), any());
			verify(pstmt, times(count)).executeUpdate();
			verify(pstmt).setString(1, products.get(count-1).getCveId());
		} catch (SQLException ignored) {}
	}

	@Test
	public void getAllCompositeVulnerabilitiesTest() throws SQLException {
		// Prepare test data
		int maxVulnerabilities = 5;
		int expectedVulnerabilities = 3;

		// Mock the database interactions
		when(conn.prepareStatement(anyString())).thenReturn(pstmt);
		when(pstmt.executeQuery()).thenReturn(res);
		when(res.next()).thenReturn(true, true, true, false); // Simulate 3 rows returned from the query, followed by an extra call returning false
		when(res.getInt("vuln_id")).thenReturn(1, 2, 3);
		when(res.getString("cve_id")).thenReturn("CVE-2021-001", "CVE-2021-002", "CVE-2021-003");
		when(res.getString("description")).thenReturn("Description 1", "Description 2", "Description 3");

		// Call the method under test
		List<CompositeVulnerability> result = dbh.getAllCompositeVulnerabilities(maxVulnerabilities);

		// Verify the expected interactions
		verify(conn).prepareStatement(anyString());
		verify(pstmt).executeQuery();
		verify(res, times(expectedVulnerabilities)).getInt("vuln_id");
		verify(res, times(expectedVulnerabilities)).getString("cve_id");
		verify(res, times(expectedVulnerabilities)).getString("description");

		// Verify the result
		assertEquals(expectedVulnerabilities, result.size());
	}

	@Test
	public void getSpecificCompositeVulnerabilitiesTest() throws SQLException{
		List<String> cveIds = new ArrayList<>();

		String cveId1 = "CVE-2021-20105";
		String description1 = "Machform prior to version 16 is vulnerable to an open redirect in Safari_init.php due to an improperly sanitized 'ref' parameter.";

		String cveId2 = "CVE-2016-4361";
		String description2 = "HPE LoadRunner 11.52 through patch 3, 12.00 through patch 1, 12.01 through patch 3, 12.02 through patch 2, and 12.50 through patch 3 and Performance Center 11.52 through patch 3, 12.00 through patch 1, 12.01 through patch 3, 12.20 through patch 2, and 12.50 through patch 1 allow remote attackers to cause a denial of service via unspecified vectors.";

		String cveId3 = "CVE-2019-3915";
		String description3 = "Authentication Bypass by Capture-replay vulnerability in Verizon Fios Quantum Gateway (G1100) firmware version 02.01.00.05 allows an unauthenticated attacker with adjacent network access to intercept and replay login requests to gain access to the administrative web interface.";

		cveIds.add(cveId1);
		cveIds.add(cveId2);
		cveIds.add(cveId3);

		// Mock the database interactions
		when(conn.prepareStatement(anyString())).thenReturn(pstmt);
		when(pstmt.executeQuery()).thenReturn(res);
		when(res.next()).thenReturn(true, true, true, false);
		when(res.getInt("vuln_id")).thenReturn(1, 2, 3);
		when(res.getString("description")).thenReturn(description1, description2, description3);

		List<CompositeVulnerability> vulnList = dbh.getSpecificCompositeVulnerabilities(cveIds);
		assertEquals(vulnList.size(), cveIds.size());

		CompositeVulnerability vuln1 = vulnList.get(0);
		CompositeVulnerability vuln2 = vulnList.get(1);
		CompositeVulnerability vuln3 = vulnList.get(2);

		assertEquals(vuln1.getDescription(), description1);
		assertEquals(vuln2.getDescription(), description2);
		assertEquals(vuln3.getDescription(), description3);
	}

	@Test
	public void shutdownTest() {
		dbh.shutdown();
		verify(hds).close();
	}
}
