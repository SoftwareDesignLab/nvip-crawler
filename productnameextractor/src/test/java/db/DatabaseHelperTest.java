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
import com.zaxxer.hikari.HikariPoolMXBean;
import model.AffectedRelease;
import model.Product;
import model.Vulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
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

	@BeforeClass
	public static void classSetUp() {
		// forces a constructor, only want to do once
		DatabaseHelper.getInstance();
	}

	@Before
	public void setUp() {
		this.dbh = DatabaseHelper.getInstance();
		ReflectionTestUtils.setField(this.dbh, "dataSource", this.hds);
		this.setMocking();
	}

	@AfterClass
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
	public void insertCpeProductsTest() {
		List<Product> testProducts = new ArrayList<>();
		String domain = "domain";
		String cpe = "cpe";
		for (int i=0; i < 5; i++) {
			testProducts.add(new Product(domain+i, cpe+i));
		}
		try {
			setResNextCount(0);
			when(pstmt.executeUpdate()).thenReturn(1);
			int count1 = dbh.insertCpeProducts(testProducts.subList(0,1));
			assertEquals(1, count1);

			int n_existing = 1;
			setResNextCount(n_existing);
			when(res.getInt(1)).thenReturn(n_existing);
			int count2 = dbh.insertCpeProducts(testProducts);
			assertEquals(4, count2);
			verify(pstmt, times(2)).setString(1, cpe+4);
			verify(pstmt).setString(2, domain+4);
		} catch (SQLException ignored) {}
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

	@Test
	public void insertAffectedReleasesV2Test() {
		int inCount = 5;
		List<AffectedRelease> releases = buildDummyReleases(inCount);
		dbh.insertAffectedReleasesV2(releases);
		try {
			verify(pstmt, atLeast(inCount*3)).setString(anyInt(), any());
			verify(pstmt, times(inCount)).setInt(anyInt(), anyInt());
			verify(pstmt, times(inCount)).executeUpdate();
			verify(pstmt).setString(4, releases.get(0).getVersion());
		} catch (SQLException ignored) {}
	}

	@Test
	public void deleteAffectedReleasesTest() {
		int count = 5;
		List<AffectedRelease> releases = buildDummyReleases(count);
		dbh.deleteAffectedReleases(releases);
		try {
			verify(pstmt, times(count)).setString(anyInt(), any());
			verify(pstmt, times(count)).executeUpdate();
			verify(pstmt).setString(1, releases.get(count-1).getCveId());
		} catch (SQLException ignored) {}
	}

	@Test
	public void shutdownTest() {
		dbh.shutdown();
		verify(hds).close();
	}
}
