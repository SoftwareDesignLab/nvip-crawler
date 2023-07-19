package productdetection; /**
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

import env.ProductNameExtractorEnvVars;
import model.cve.CompositeVulnerability;
import model.cpe.CpeGroup;
import org.junit.Test;
import dictionary.ProductDictionary;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertTrue;

/**
 * Test affectedproductidentifier.AffectedProductIdentifier
 * @author axoeec
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
		CompositeVulnerability v = new CompositeVulnerability(0, null, "CVE-2017-12794", "", null, null, description, CompositeVulnerability.CveReconcileStatus.UPDATE);
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
		affectedProductIdentifier.identifyAffectedProducts();

		System.out.println(v.getAffectedProducts());

		assertTrue("Test failed: No affected releases found", (v.getAffectedProducts().size() > 0));
	}

}
