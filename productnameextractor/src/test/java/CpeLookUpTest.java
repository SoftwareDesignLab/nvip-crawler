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

import model.cpe.CpeEntry;
import model.cpe.CpeGroup;
import model.cpe.ProductItem;
import model.cpe.ProductVersion;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for the CpeLookUp class
 *
 * @author Igor Khokhlov
 *
 */

public class CpeLookUpTest {
	// Init cpeLookUp
	private static final CpeLookUp cpeLookUp = new CpeLookUp();
	static {
		try {
			final Map<String, CpeGroup> productDict = ProductNameExtractorController.readProductDict("src/test/resources/data/product_dict.json");
			cpeLookUp.loadProductDict(productDict);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}


	@Test
	public void legitimateProduct() {
		ProductItem product = new ProductItem("phpMyAdmin");
		product.addVersion("4.1.5");

		String expectedResult = "cpe:2.3:a:phpmyadmin:phpmyadmin:4.1.5:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull("idList was null", idList);
		assertNotEquals("idList was empty", idList.size(), 0);
		assertEquals("actual result was not expected result", expectedResult, idList.get(0));
	}

	@Test
	public void legitimateComplexProduct() {
		ProductItem product = new ProductItem("cacheos.");
		product.addVersion("before");
		product.addVersion("4.0");

		String expectedResult = "cpe:2.3:a:bluecoat:cacheos:4.0:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull("idList was null", idList);
		assertNotEquals("idList was empty", idList.size(), 0);
		assertEquals("actual result was not expected result", expectedResult, idList.get(0));
	}

	@Test
	public void legitimateComplexProduct2() {
		ProductItem product = new ProductItem("phpMyAdmin:.");
		product.addVersion("https://www.openwall.com/lists/oss-security/2012/05/10/6");
		product.addVersion("before");
		product.addVersion("3.3.4.0");

		String expected = "cpe:2.3:a:phpmyadmin:phpmyadmin:3.3.4.0:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull("idList was null", idList);
		assertNotEquals("idList was empty", idList.size(), 0);
		assertEquals("actual result was not expected result", expected, idList.get(0));

	}

	@Test
	public void legitimateComplexProduct3() {
		ProductItem product = new ProductItem("the Linux.");
		product.addVersion("https://www.openwall.com/lists/oss-security/2012/05/10/6");

		String expectedResult = "cpe:2.3:a:redhat:linux:*:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull("idList was null", idList);
		assertNotEquals("idList was empty", idList.size(), 0);
		assertEquals("actual result was not expected result", expectedResult, idList.get(0));
	}

	@Test
	public void legitimateComplexProductMultipleVersions() {
		ProductItem product = new ProductItem("phpMyAdmin.");
		product.addVersion("4.8.0.1");
		product.addVersion("4.8.4");
		product.addVersion("4.7.9");

		String expectedResult1 = "cpe:2.3:a:phpmyadmin:phpmyadmin:4.8.0.1:*:*:*:*:*:*:*";
		String expectedResult2 = "cpe:2.3:a:phpmyadmin:phpmyadmin:4.8.4:*:*:*:*:*:*:*";
		String expectedResult3 = "cpe:2.3:a:phpmyadmin:phpmyadmin:4.7.9:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull("idList was null", idList);
		assertNotEquals("idList was empty", idList.size(), 0);
		assertEquals("actual result was not expected result", expectedResult1, idList.get(0));
		assertEquals("actual result was not expected result", expectedResult2, idList.get(1));
		assertEquals("actual result was not expected result", expectedResult3, idList.get(2));
	}

	@Test
	public void legitimateComplexProductNoVersion() {
		ProductItem product = new ProductItem("Canon ImageRunner 5000i");

		String expectedResult = "cpe:2.3:a:canon:imagerunner:*:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull("idList was null", idList);
		assertNotEquals("idList was empty", idList.size(), 0);
		assertEquals("actual result was not expected result", expectedResult, idList.get(0));
	}

	@Test
	public void checkSNVerification() {
		String sn1 = "Explorer.";
		String sn2 = "Linux";

		List<String> sn1List = cpeLookUp.getCPETitles(sn1);
		List<String> sn2List = cpeLookUp.getCPETitles(sn2);

		assertNotNull("sn1List was null", sn1List);
		assertNotNull("sn2List was null", sn2List);
		assertNotEquals("sn1List was empty", sn1List.size(), 0);
		assertNotEquals("sn2List was empty", sn2List.size(), 0);
	}

	@Test
	public void queryProductDictTest() {
		int maxPages = 2;
		int maxAttemptsPerPage = 3;
		// Call the method to load the product dictionary
		Map<String, CpeGroup> loadedDict = cpeLookUp.queryProductDict(maxPages, maxAttemptsPerPage);

		// Assert that the loaded dictionary is not null
		Assertions.assertNotNull(loadedDict);

		// Assert that the loaded dictionary is not empty
		Assertions.assertFalse(loadedDict.isEmpty());

		// Retrieve a CpeGroup by key
		String key = "canon:imagerunner_5000i";
		CpeGroup cpeGroup = loadedDict.get(key);
		System.out.println(cpeGroup);
		// Assert that the CpeGroup is not null
		Assertions.assertNotNull(cpeGroup);

		// Assert that the CpeGroup has versions
		Assertions.assertTrue(cpeGroup.getVersions().size() > 0);

		// Assert that a specific version exists in the CpeGroup
		Assertions.assertTrue(cpeGroup.getVersions().containsKey("-"));

		// Retrieve a specific CpeEntry from the CpeGroup
		CpeEntry cpeEntry = cpeGroup.getVersions().get("-");

		// Assert that the CpeEntry is not null
		Assertions.assertNotNull(cpeEntry);

		// Assert specific properties of the CpeEntry
		Assertions.assertEquals("imagerunner_5000i", cpeEntry.getTitle());
		Assertions.assertEquals("-", cpeEntry.getVersion());
		Assertions.assertEquals("88FD64E8-67E8-415D-A798-4DC26EA8E7B5", cpeEntry.getCpeID());

		// Perform similar assertions for other keys, CpeGroups, and CpeEntries in the loaded dictionary
	}

}