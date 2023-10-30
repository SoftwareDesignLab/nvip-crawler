package productdetection;

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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import model.cpe.CpeGroup;
import model.cpe.ProductItem;
import dictionary.ProductDictionary;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the CpeLookUp class
 *
 * @author Igor Khokhlov
 * @author Richard Sawh
 * @author Paul Vickers
 *
 */

public class CpeLookUpTest {
	// Init cpeLookUp
	private static CpeLookUp cpeLookUp;

	@BeforeAll
	static void initCpeLookUp(){
		cpeLookUp = new CpeLookUp();
		try {
			final Map<String, CpeGroup> productDict = ProductDictionary.readProductDict("src/test/resources/data/test_product_dict.json"); //src/test/resources/data/test_product_dict.json
			cpeLookUp.loadProductDict(productDict);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	public void legitimateProduct() {
		ProductItem product = new ProductItem("redhat linux");
		product.addVersion("6.0");

		String expectedResult = "cpe:2.3:a:redhat:linux:6.0:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull(idList, "idList was null");
		assertNotEquals(idList.size(), 0, "idList was empty");
		assertEquals(expectedResult, idList.get(0), "actual result was not expected result");
	}

	@Test
	public void legitimateComplexProduct() {
		ProductItem product = new ProductItem("banking_loans_servicing");
		product.addVersion("before");
		product.addVersion("4.0");

		String expectedResult = "cpe:2.3:a:oracle:banking_loans_servicing:2.12.0:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull(idList, "idList was null");
		assertNotEquals(idList.size(), 0, "idList was empty");
		assertEquals(expectedResult, idList.get(0), "actual result was not expected result");
	}

	@Test
	public void legitimateComplexProduct2() {
		ProductItem product = new ProductItem("linux:.");
		product.addVersion("https://www.openwall.com/lists/oss-security/2012/05/10/6");
		product.addVersion("before");
		product.addVersion("1.0");

		String expected = "cpe:2.3:a:redhat:linux:1.0:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull(idList, "idList was null");
		assertNotEquals(idList.size(), 0, "idList was empty");
		assertEquals(expected, idList.get(0), "actual result was not expected result");

	}

	@Test
	public void legitimateComplexProduct3() {
		ProductItem product = new ProductItem("the Linux.");
		product.addVersion("https://www.openwall.com/lists/oss-security/2012/05/10/6");

		String expectedResult = "cpe:2.3:a:redhat:linux:*:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull(idList, "idList was null");
		assertNotEquals(idList.size(), 0, "idList was empty");
		assertEquals(expectedResult, idList.get(0), "actual result was not expected result");
	}

	@Test
	public void legitimateComplexProductMultipleVersions() {
		ProductItem product = new ProductItem("Redhat Linux");
		product.addVersion("3.0.3");
		product.addVersion("2.6.2");
		product.addVersion("2.0.34");

		String expectedResult1 = "cpe:2.3:a:redhat:linux:3.0.3:*:*:*:*:*:*:*";
		String expectedResult2 = "cpe:2.3:a:redhat:linux:2.6.2:*:*:*:*:*:*:*";
		String expectedResult3 = "cpe:2.3:a:redhat:linux:2.0.34:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull(idList, "idList was null");
		assertNotEquals(idList.size(), 0, "idList was empty");
		assertEquals(expectedResult1, idList.get(0), "actual result was not expected result");
		assertEquals(expectedResult2, idList.get(1), "actual result was not expected result");
		assertEquals(expectedResult3, idList.get(2), "actual result was not expected result");
	}

	@Test
	public void legitimateComplexProductNoVersion() {
		ProductItem product = new ProductItem("gentoo xnview");

		String expectedResult = "cpe:2.3:a:gentoo:xnview:*:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEIds(product);

		assertNotNull(idList, "idList was null");
		assertNotEquals(idList.size(), 0, "idList was empty");
		assertEquals(expectedResult, idList.get(0), "actual result was not expected result");
	}

	@Test
	public void checkSNVerification() {
		String sn1 = "XNVIEW.";
		String sn2 = "Linux";

		List<String> sn1List = cpeLookUp.getCPETitles(sn1);
		List<String> sn2List = cpeLookUp.getCPETitles(sn2);

		assertNotNull(sn1List, "sn1List was null");
		assertNotNull(sn2List, "sn2List was null");
		assertNotEquals(sn1List.size(), 0, "sn1List was empty");
		assertNotEquals(sn2List.size(), 0, "sn2List was empty");
	}

}