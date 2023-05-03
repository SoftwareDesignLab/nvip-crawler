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
package edu.rit.se.nvip.db;

import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.model.*;
import edu.rit.se.nvip.model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.*;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.Date;


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
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

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
			when(pstmt.executeQuery(any())).thenReturn(res);
		} catch (SQLException ignored) {}
	}

	/**
	 * Sets up the "databse" results to return n rows
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

	/**
	 * Helper method for populating the "database" results.
	 * @param getStringArg Name of the column to retrieve from. Used for that column's value as well with a suffix.
	 * @param count Number of results to populate.
	 */
	private void setResStrings(String getStringArg, int count) {
		try {
			when(res.getString(getStringArg)).thenAnswer(new Answer<String>() {
				private int index = 0;

				public String answer(InvocationOnMock invocation) {
					if (index == count) {
						return null;
					}
					return getStringArg + index++;
				}
			});
		} catch (SQLException ignored) {}
	}

	/**
	 * Helper method for populating the "database" results. Just returns multiples of 1337
	 * @param getIntArg Name of the column to retrieve from.
	 * @param count Number of results to populate.
	 */
	private void setResInts(String getIntArg, int count) {
		try {
			when(res.getInt(getIntArg)).thenAnswer(new Answer<Integer>() {
				private int index = 0;

				public Integer answer(InvocationOnMock invocation) {
					if (index == count) {
						return 0;
					}
					return 1337 * index++;
				}
			});
		} catch (SQLException ignored) {}
	}

	private List<AffectedRelease> buildDummyReleases(int count) {
		List<AffectedRelease> releases = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			releases.add(new AffectedRelease(1337, "cve"+i, "cpe"+i, "date"+i, "version"+i));
		}
		return releases;
	}

	@org.junit.BeforeClass
	public static void classSetUp() {
		// forces a constructor, only want to do once
		DatabaseHelper.getInstance();
	}

	@org.junit.Before
	public void setUp() {
		this.dbh = DatabaseHelper.getInstance();
		ReflectionTestUtils.setField(this.dbh, "dataSource", this.hds);
		this.setMocking();
	}

	@org.junit.AfterClass
	public static void tearDown() {
		DatabaseHelper dbh = DatabaseHelper.getInstance();
		ReflectionTestUtils.setField(dbh, "databaseHelper", null);

	}

	@Test
	public void getInstanceTest() {
		assertNotNull(DatabaseHelper.getInstance());
	}

	@Test
	public void getConnectionTest() {
		try {
			Connection conn = dbh.getConnection();
			assertNotNull(conn);
		} catch (SQLException ignored) {}
	}

	@Test
	public void testDbConnectionTest() {
		try {
			assertTrue(this.dbh.testDbConnection());
			when(hds.getConnection()).thenReturn(null);
			assertFalse(this.dbh.testDbConnection());
		} catch (SQLException ignored) {
		}
	}

	@Test
	public void getExistingVulnerabilitiesTest() {
		// static field so need to reset to retain test independence
		ReflectionTestUtils.setField(this.dbh, "existingVulnMap", new HashMap<String, Vulnerability>());
		int count = 5;
		setResNextCount(count);
		setResInts("vuln_id", count);
		setResStrings("cve_id", count);
		setResStrings("description", count);
		setResStrings("created_date", count);
		setResInts("exists_at_nvd", count);
		setResInts("exists_at_mitre", count);

		Map<String, Vulnerability> vulns = dbh.getExistingVulnerabilities();
		assertEquals(count, vulns.size());
		assertTrue(vulns.containsKey("cve_id4"));
		assertEquals(1337*4, vulns.get("cve_id4").getVulnID());
		assertEquals("cve_id4", vulns.get("cve_id4").getCveId());
		assertEquals("description4", vulns.get("cve_id4").getDescription());
		assertEquals("created_date4", vulns.get("cve_id4").getCreateDate());
		assertTrue(vulns.get("cve_id4").doesExistInNvd());
		assertTrue(vulns.get("cve_id4").doesExistInMitre());
		try {
			verify(pstmt).executeQuery();
		} catch (SQLException ignored) {}
		// should pull the vulnerabilities from memory instead of the db
		vulns = dbh.getExistingVulnerabilities();
		assertEquals(count, vulns.size());
		verifyNoMoreInteractions(pstmt);
	}

	@Test
	public void insertVulnerabilityUpdateTest() {
		boolean success = dbh.insertVulnerabilityUpdate(1337, "description", "descriptionval", 1111);
		assertTrue(success);
		try {
			verify(pstmt).setInt(1, 1337);
			verify(pstmt).setString(2, "description");
			verify(pstmt).setString(3, "descriptionval");
			verify(pstmt).setInt(4, 1111);
			verify(pstmt).executeUpdate();
		} catch (SQLException ignored) {}
	}

	@Test
	public void getNvipCveSourcesTest() {
		setResNextCount(3);
		setResInts("source_id", 3);
		setResStrings("url", 3);
		setResStrings("description", 3);
		setResInts("http_status", 3);
		ArrayList<NvipSource> sources = dbh.getNvipCveSources();
		assertEquals(3, sources.size());
		NvipSource testSource = sources.get(2);
		assertEquals(1337*2, testSource.getSourceId());
		assertEquals("url2", testSource.getUrl());
		assertEquals("description2", testSource.getDescription());
		assertEquals(1337*2, testSource.getHttpStatus());
	}

	@Test
	public void getActiveConnectionsTest() {
		HikariPoolMXBean bean = mock(HikariPoolMXBean.class);
		when(hds.getHikariPoolMXBean()).thenReturn(bean);
		when(bean.getActiveConnections()).thenReturn(5);
		int n = dbh.getActiveConnections();
		assertEquals(5, n);
	}

	@Test
	public void getIdleConnectionsTest() {
		HikariPoolMXBean bean = mock(HikariPoolMXBean.class);
		when(hds.getHikariPoolMXBean()).thenReturn(bean);
		when(bean.getIdleConnections()).thenReturn(6);
		int n = dbh.getIdleConnections();
		assertEquals(6, n);
	}

	@Test
	public void getTotalConnectionsTest() {
		HikariPoolMXBean bean = mock(HikariPoolMXBean.class);
		when(hds.getHikariPoolMXBean()).thenReturn(bean);
		when(bean.getTotalConnections()).thenReturn(11);
		int n = dbh.getTotalConnections();
		assertEquals(11, n);
	}

	@Test
	public void getConnectionStatusTest() {
		HikariPoolMXBean bean = mock(HikariPoolMXBean.class);
		when(hds.getHikariPoolMXBean()).thenReturn(bean);
		when(bean.getActiveConnections()).thenReturn(5);
		when(bean.getIdleConnections()).thenReturn(6);
		when(bean.getTotalConnections()).thenReturn(11);
		String connStatus = dbh.getConnectionStatus();
		assertEquals("[5,6]=11", connStatus);
	}

	@Test
	public void shutdownTest() {
		dbh.shutdown();
		verify(hds).close();
	}


	@Test
	public void getCveIdTest() {
		setResNextCount(1);
		setResStrings("cve_id", 1);
		try {
			String out = dbh.getCveId("8888");
			verify(pstmt).setInt(1, 8888);
			assertEquals("cve_id0", out);
		} catch (SQLException ignored) {}
	}
}
