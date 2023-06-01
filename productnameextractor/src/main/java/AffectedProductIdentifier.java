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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import model.*;
import db.*;

import opennlp.tools.tokenize.WhitespaceTokenizer;

/**
 * @author axoeec
 *
 */
public class AffectedProductIdentifier {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	private final List<CompositeVulnerability> vulnList;

	public AffectedProductIdentifier(List<CompositeVulnerability> vulnList) {
		this.vulnList = vulnList;
	}

	/**
	 * insert CPE products identified by the loader into the database
	 * TODO: Should be in DB Helper
	 */
	private int insertNewCpeItemsIntoDatabase() {
		CpeLookUp cpeLookUp = CpeLookUp.getInstance();
		try {
			Collection<Product> products = cpeLookUp.getProductsToBeAddedToDatabase().values();
			DatabaseHelper db = DatabaseHelper.getInstance();
			return db.insertCpeProducts(products);
		} catch (Exception e) {
			logger.error("Error while adding " + cpeLookUp.getProductsToBeAddedToDatabase().size() + " new products!");
			return -1;
		}

	}

	public int identifyAffectedReleases() {
		logger.info("Starting to identify affected products for " + vulnList.size() + " CVEs.");
		long start = System.currentTimeMillis();

		DetectProducts productNameDetector;
		try {
			productNameDetector = DetectProducts.getInstance();
		} catch (Exception e1) {
			logger.error("Severe Error! Could not initialize the models for product name/version extraction! Skipping affected release identification step! {}", e1.toString());
			return -1;
		}

		CpeLookUp cpeLookUp = CpeLookUp.getInstance();
		int numOfProductsMappedToCpe = 0;
		int numOfProductsNotMappedToCPE = 0;
		int counterOfProcessedNERs = 0;
		int counterOfProcessedCPEs = 0;
		int counterOfProcessedCVEs = 0;
		int counterOfSkippedCVEs = 0;
		int counterOfBadDescriptionCVEs = 0;
		long totalNERtime = 0;
		long totalCPEtime = 0;
		long totalCVEtime = 0;

		int totalCVEtoProcess = vulnList.size();

		logger.info("Starting product name extraction process... # CVEs to be processed: {}", totalCVEtoProcess);

		// Default value of 1000, attempts to get the limit value from env vars and override this value
		int cveLimit = 1000;
		try { cveLimit = Integer.parseInt(System.getenv("CVE_LIMIT")); }
		catch (NullPointerException | NumberFormatException e) {
			logger.warn("Could not fetch CVE_LIMIT from env vars, defaulting to 1000");
		}

		for (CompositeVulnerability vulnerability : vulnList) {

			String description = vulnerability.getDescription();

			if (description == null || description.length() == 0) {
				counterOfBadDescriptionCVEs++;
				continue; // skip the ones without a description
			}

			// if a CVE did change, no need to extract products, assuming they are
			// already in DB!!
			if (vulnerability.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE) {
				counterOfSkippedCVEs++;
				continue;
			}

			counterOfProcessedCVEs++;

			if (counterOfProcessedCVEs > cveLimit)
				break;

			long startCVETime = System.currentTimeMillis();
			try {
				// LIMIT to 100 words
				String[] descriptionWords = WhitespaceTokenizer.INSTANCE.tokenize(description);

				int maxDescLengthWords = 100;
				if (descriptionWords.length > maxDescLengthWords) {
					String[] subStringArray = new String[maxDescLengthWords];
					System.arraycopy(descriptionWords, 0, subStringArray, 0, maxDescLengthWords);
					descriptionWords = subStringArray;
				}

				// if no products found by crawlers, use AI/ML model to extract product/version
				// from text
				if (vulnerability.getAffectedReleases() == null || vulnerability.getAffectedReleases().isEmpty()) {

					// Time measurement
					long startNERTime = System.currentTimeMillis();

					// get products from AI/ML model
					List<ProductItem> productList = productNameDetector.getProductItems(descriptionWords);

					long nerTime = System.currentTimeMillis() - startNERTime;
					counterOfProcessedNERs++;
					totalNERtime = totalNERtime + nerTime;

					// map identified products/version to CPE
					for (ProductItem productItem : productList) {

						long startCPETime = System.currentTimeMillis();
						List<String> productIDs = cpeLookUp.getCPEids(productItem);
						long cpeTime = System.currentTimeMillis() - startCPETime;
						totalCPEtime = totalCPEtime + cpeTime;
						counterOfProcessedCPEs++;

						if (productIDs == null || productIDs.isEmpty()) {
							numOfProductsNotMappedToCPE++;
							logger.warn("The product name ({}) predicted by AI/ML model could not be found in the CPE dictionary!\tCVE-ID: {}", productItem.toString(), vulnerability.getCveId());
							continue;
						}
						// if CPE identified, add it as affected release
						for (String itemID : productIDs) {
//							logger.info("Found Affected Product for {}: {}", vulnerability.getCveId(), itemID);
							vulnerability.getAffectedReleases().add(new AffectedRelease(0, vulnerability.getCveId(), itemID, vulnerability.getPublishDate(), CpeLookUp.getVersionFromCPEid(itemID), CpeLookUp.getVendorFromCPEid(itemID)));
							numOfProductsMappedToCpe++;
						}
					}

					// set platform string
					// TODO change this so it actually adds something to platform
					vulnerability.setPlatform("");
				}

			} catch (Exception e) {
				// TODO: This error gets hit for every CVE

				//logger.error("Error {} while extracting affected releases! Processed: {} out of {} CVEs; CVE: {}", e, Integer.toString(counterOfProcessedCVEs), Integer.toString(totalCVEtoProcess),
				//		vulnerability.toString());
			}

			totalCVEtime = totalCVEtime + (System.currentTimeMillis() - startCVETime);

			if (counterOfProcessedCVEs % 100 == 0) {
				double percent = Math.floor(((double) (counterOfProcessedCVEs + counterOfBadDescriptionCVEs + counterOfSkippedCVEs) / totalCVEtoProcess * 100) * 100) / 100;
				logger.info("Extracted product(s) for {} out of {} CVEs so far! {} CVEs skipped (not-changed or bad description), {}% done.", counterOfProcessedCVEs, totalCVEtoProcess,
						(counterOfBadDescriptionCVEs + counterOfSkippedCVEs), percent);
			}
		}


		logger.info("Extracted product(s) for {} out of {} CVEs so far! {} CVEs skipped, bc they are flagged as 'not-changed' by reconciliation process", counterOfProcessedCVEs, totalCVEtoProcess,
				counterOfSkippedCVEs);

		AtomicInteger count = new AtomicInteger();
		vulnList.stream().map(v -> v.getAffectedReleases().size()).forEach(count::addAndGet);
		logger.info("Found {} affected releases from {} CVEs", count, totalCVEtoProcess);

		// TODO: This function should be called outside
		insertAffectedProductsToDB(vulnList);

		return numOfProductsMappedToCpe;

	}

	/**
	 * Store affected products in DB
	 * TODO: This should be in DB Helper
	 * @param vulnList
	 */
	public void insertAffectedProductsToDB(List<CompositeVulnerability> vulnList) {
		// refresh db conn, it might be timed out if the process takes so much time!
		DatabaseHelper databaseHelper = DatabaseHelper.getInstance();

		logger.info("Inserting found products to DB!");
		insertNewCpeItemsIntoDatabase();

		// get all identified affected releases
		List<AffectedRelease> listAllAffectedReleases = new ArrayList<>();
		for (CompositeVulnerability vulnerability : vulnList) {
			if (vulnerability.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE)
				continue; // skip the ones that are not changed!
			listAllAffectedReleases.addAll(vulnerability.getAffectedReleases());
		}

		logger.info("Inserting Affected Releases to DB!");
		// delete existing affected release info in db ( for CVEs in the list)
		databaseHelper.deleteAffectedReleases(listAllAffectedReleases);

		// now insert affected releases (referenced products are already in db)
		databaseHelper.insertAffectedReleasesV2(listAllAffectedReleases);

//		// prepare CVE summary table for Web UI
//		// TODO: This should be in NVIPMAIN
//		logger.info("Preparing CVE summary table for Web UI...");
//		PrepareDataForWebUi cveDataForWebUi = new PrepareDataForWebUi();
//		cveDataForWebUi.prepareDataforWebUi();

		databaseHelper.shutdown();
	}

}
