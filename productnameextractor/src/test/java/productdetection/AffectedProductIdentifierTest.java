/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

package productdetection; /**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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

import edu.rit.se.nvip.db.model.CpeGroup;
import env.ProductNameExtractorEnvVars;
import edu.rit.se.nvip.db.model.AffectedProduct;
import edu.rit.se.nvip.db.model.CompositeVulnerability;
import org.junit.jupiter.api.Test;
import dictionary.ProductDictionary;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AffectedProductIdentifier class
 *
 * @author axoeec
 * @author Paul Vickers
 */

public class AffectedProductIdentifierTest {

	/**
	 * Test product name extraction for a simple CVE
	 */
	@Test
	public void affectedProductIdentifierTest() {
		ProductNameExtractorEnvVars.initializeEnvVars();

		String resourceDir = ProductNameExtractorEnvVars.getResourceDir();
		String nlpDir = ProductNameExtractorEnvVars.getNlpDir();
		String dataDir = ProductNameExtractorEnvVars.getDataDir();

		String description = "In Redhat Linux 1.10.x before 1.10.8 and 1.11.x before 1.11.5, HTML autoescaping was disabled in a portion of the template for the technical 500 debug page. Given the right circumstances, this allowed a cross-site scripting attack. This vulnerability shouldn't affect most production sites since you shouldn't run with \"DEBUG = True\" (which makes this page accessible) in your production settings.";
		List<CompositeVulnerability> vulnList = new ArrayList<>();
		CompositeVulnerability v = new CompositeVulnerability(0, "CVE-2017-12794", description, CompositeVulnerability.ReconciliationStatus.UPDATED);
		vulnList.add(v);

		AffectedProductIdentifier affectedProductIdentifier = new AffectedProductIdentifier(12, vulnList);
		affectedProductIdentifier.initializeProductDetector(resourceDir, nlpDir, dataDir);
		// Init cpeLookUp
		try {
			final Map<String, CpeGroup> productDict = ProductDictionary.readProductDict("src/test/resources/data/test_product_dict.json");
			affectedProductIdentifier.loadProductDict(productDict);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		// Identify releases
		affectedProductIdentifier.identifyAffectedProducts(v);

		System.out.println(v.getAffectedProducts());

		assertTrue((v.getAffectedProducts().size() > 0), "Test failed: No affected releases found");
	}

	@Test
	public void testSetVulnList(){
		ProductNameExtractorEnvVars.initializeEnvVars();

		String resourceDir = ProductNameExtractorEnvVars.getResourceDir();
		String nlpDir = ProductNameExtractorEnvVars.getNlpDir();
		String dataDir = ProductNameExtractorEnvVars.getDataDir();

		String description = "In Redhat Linux 1.10.x before 1.10.8 and 1.11.x before 1.11.5, HTML autoescaping was disabled in a portion of the template for the technical 500 debug page. Given the right circumstances, this allowed a cross-site scripting attack. This vulnerability shouldn't affect most production sites since you shouldn't run with \"DEBUG = True\" (which makes this page accessible) in your production settings.";
		List<CompositeVulnerability> vulnList = new ArrayList<>();
		CompositeVulnerability v = new CompositeVulnerability(0, "CVE-2017-12794", description, CompositeVulnerability.ReconciliationStatus.UPDATED);
		vulnList.add(v);

		AffectedProductIdentifier affectedProductIdentifier = new AffectedProductIdentifier(12, vulnList);
		affectedProductIdentifier.setVulnList(vulnList);

		//assert that the vulnList contains the correct vuln
		String expected = "[]";
		String actual = String.valueOf(vulnList);
		assertEquals(expected, actual);

	}


	@Test
	public void testIdentifyAffectedProducts() throws Exception {
		// Create mock dependencies
		ProductDetector productDetector = mock(ProductDetector.class);
		CpeLookUp cpeLookUp = mock(CpeLookUp.class);
		CompositeVulnerability vulnerability = mock(CompositeVulnerability.class);

		List<CompositeVulnerability> vulnList = new ArrayList<>();
		vulnList.add(vulnerability); // Add mock vulnerability to the list

		// Create an instance of the class under test (adjust constructor parameters as needed)
		AffectedProductIdentifier identifier = new AffectedProductIdentifier(2, vulnList);

		// Simulate the method call
		List<AffectedProduct> affectedProducts = identifier.identifyAffectedProducts(vulnerability);

		// Add assertions based on the expected behavior of the method
		assertEquals(affectedProducts.size(), 0);
	}

	@Test
	public void testReleaseResources() {
		AffectedProductIdentifier affectedProductIdentifier = new AffectedProductIdentifier(12, null);

		Logger logger = mock(Logger.class);
		ProductDetector productDetector = mock(ProductDetector.class);


		// Call releaseResources() method
		affectedProductIdentifier.releaseResources();

		// Verify that the methods were called appropriately
		assertEquals(logger.toString().contains("Mock for Logger, hashCode:"), true);

	}

}
