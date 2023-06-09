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

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import model.*;

import opennlp.tools.tokenize.WhitespaceTokenizer;

/**
 * @author axoeec
 * @author Dylan Mulligan
 */
public class AffectedProductIdentifier {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	private final List<CompositeVulnerability> vulnList;
	private final CpeLookUp cpeLookUp;

	public AffectedProductIdentifier(List<CompositeVulnerability> vulnList) {
		this.vulnList = vulnList;
		this.cpeLookUp = new CpeLookUp();
	}

	private void processVulnerability(
			DetectProducts productNameDetector,
			CpeLookUp cpeLookUp,
			CompositeVulnerability vulnerability,
			AtomicInteger counterOfBadDescriptionCVEs,
			AtomicInteger counterOfSkippedCVEs, AtomicInteger counterOfProcessedCVEs,
			AtomicInteger counterOfProcessedNERs,
			AtomicInteger counterOfProcessedCPEs,
			AtomicInteger numOfProductsNotMappedToCPE,
			AtomicInteger numOfProductsMappedToCpe,
			AtomicLong totalNERTime,
			AtomicLong totalCPETime,
			AtomicLong totalCVETime,
			int totalCVEtoProcess
	) {
		String description = vulnerability.getDescription();

		if (description == null || description.length() == 0) {
			counterOfBadDescriptionCVEs.getAndIncrement();
			return; // skip the ones without a description
		}

		// if a CVE did change, no need to extract products, assuming they are
		// already in DB!!
		if (vulnerability.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE) {
			counterOfSkippedCVEs.getAndIncrement();
			return;
		}

		counterOfProcessedCVEs.getAndIncrement();

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

			// Get list of existing releases and ensure it is not null (should be empty list instead)
			final List<AffectedRelease> existingReleases = vulnerability.getAffectedReleases();
			assert existingReleases != null;

			// if no products found by crawlers, use AI/ML model to extract product/version
			// from text
			if (existingReleases.isEmpty()) {

				// Time measurement
				long startNERTime = System.currentTimeMillis();

				// get products from AI/ML model
				List<ProductItem> productList = productNameDetector.getProductItems(descriptionWords);

				long nerTime = System.currentTimeMillis() - startNERTime;
				counterOfProcessedNERs.getAndIncrement();
				totalNERTime.addAndGet(nerTime);

				// map identified products/version to CPE
				for (ProductItem productItem : productList) {
					long startCPETime = System.currentTimeMillis();
					List<String> productIDs = cpeLookUp.getCPEIds(productItem);
					long cpeTime = System.currentTimeMillis() - startCPETime;
					totalCPETime.addAndGet(cpeTime);
					counterOfProcessedCPEs.getAndIncrement();

					if (productIDs == null || productIDs.isEmpty()) {
						numOfProductsNotMappedToCPE.getAndIncrement();
						logger.warn("The product name ({}) predicted by AI/ML model could not be found in the CPE dictionary!\tCVE-ID: {}", productItem.toString(), vulnerability.getCveId());
						continue;
					}
					// if CPE identified, add it as affected release
					for (String itemID : productIDs) {
//							logger.info("Found Affected Product for {}: {}", vulnerability.getCveId(), itemID);
						existingReleases.add(new AffectedRelease(0, vulnerability.getCveId(), itemID, vulnerability.getPublishDate(), CpeLookUp.getVersionFromCPEid(itemID), CpeLookUp.getVendorFromCPEid(itemID)));
						numOfProductsMappedToCpe.getAndIncrement();
					}
				}

				// set platform string
				// TODO change this so it actually adds something to platform
				vulnerability.setPlatform("");
			}

		} catch (Exception e) {
			logger.error("Error {} while extracting affected releases! Processed: {} out of {} CVEs; CVE: {}", e, counterOfProcessedCVEs.toString(), Integer.toString(totalCVEtoProcess),
					vulnerability.toString());
		}

		totalCVETime.addAndGet(System.currentTimeMillis() - startCVETime);

		// TODO: Move to executor instead of in runnable
		if (counterOfProcessedCVEs.get() % 100 == 0) {
			double percent = Math.floor(((double) (counterOfProcessedCVEs.get() + counterOfBadDescriptionCVEs.get() + counterOfSkippedCVEs.get()) / totalCVEtoProcess * 100) * 100) / 100;
			logger.info("Extracted {} product(s) for {} out of {} CVEs so far! {} CVEs skipped (not-changed or bad description), {}% done.", numOfProductsMappedToCpe, counterOfProcessedCVEs, totalCVEtoProcess,
					(counterOfBadDescriptionCVEs.get() + counterOfSkippedCVEs.get()), percent);
		}
	}

	// TODO: Docstring
	public Map<String, Product> identifyAffectedReleases(int cveLimit) {
		logger.info("Starting to identify affected products for " + vulnList.size() + " CVEs.");
		long start = System.currentTimeMillis();


		DetectProducts productNameDetector;
		try {
			productNameDetector = new DetectProducts(this.cpeLookUp);
		} catch (Exception e1) {
			logger.error("Severe Error! Could not initialize the models for product name/version extraction! Skipping affected release identification step! {}", e1.toString());
			return null;
		}

		AtomicInteger numOfProductsMappedToCpe = new AtomicInteger();
		AtomicInteger numOfProductsNotMappedToCPE = new AtomicInteger();
		AtomicInteger counterOfProcessedNERs = new AtomicInteger();
		AtomicInteger counterOfProcessedCPEs = new AtomicInteger();
		AtomicInteger counterOfProcessedCVEs = new AtomicInteger();
		AtomicInteger counterOfSkippedCVEs = new AtomicInteger();
		AtomicInteger counterOfBadDescriptionCVEs = new AtomicInteger();
		AtomicLong totalNERTime = new AtomicLong();
		AtomicLong totalCPETime = new AtomicLong();
		AtomicLong totalCVETime = new AtomicLong();

		// Set # to process based on cveLimit. If cveLimit is 0, assume no limit.
		if(cveLimit == 0) cveLimit = Integer.MAX_VALUE;
		int totalCVEtoProcess = Math.min(vulnList.size(), cveLimit);

		logger.info("Starting product name extraction process... # CVEs to be processed: {}", totalCVEtoProcess);

		// Create a thread pool with a fixed number of threads
		ExecutorService executor = Executors.newFixedThreadPool(12);

		// Iterate through the list of vulnerabilities
		for (int i = 0; i < vulnList.size(); i++) {
			// Limit to cveLimit
			if(i >= cveLimit) break;

			CompositeVulnerability vulnerability = vulnList.get(i);
			// Submit a task to the executor to process each vulnerability
			executor.submit(() -> processVulnerability(
					productNameDetector,
					cpeLookUp,
					vulnerability,
					counterOfBadDescriptionCVEs,
					counterOfSkippedCVEs,
					counterOfProcessedCVEs,
					counterOfProcessedNERs,
					counterOfProcessedCPEs,
					numOfProductsNotMappedToCPE,
					numOfProductsMappedToCpe,
					totalNERTime,
					totalCPETime,
					totalCVETime,
					totalCVEtoProcess
			));
		}

		executor.shutdown();

		try {
			// Shut down the executor to release resources after all tasks are complete
			final int timeout = 30;
			final TimeUnit unit = TimeUnit.MINUTES;
			if(!executor.awaitTermination(30, TimeUnit.MINUTES)) {
				throw new TimeoutException(String.format("Product extraction thread pool runtime exceeded timeout value of %s %s", timeout, unit.toString()));
			}
			logger.info("Product extraction thread pool completed all jobs, shutting down...");
			executor.shutdown();
		} catch (Exception e) {
			logger.error("Product extraction failed: {}", e.toString());
		}

		logger.info("Extracted product(s) for {} out of {} CVEs so far! {} CVEs skipped", counterOfProcessedCVEs, totalCVEtoProcess, counterOfSkippedCVEs);

		AtomicInteger count = new AtomicInteger();
		vulnList.stream().map(v -> v.getAffectedReleases().size()).forEach(count::addAndGet);
		logger.info("Found {} affected releases from {} CVEs in {} seconds", count, totalCVEtoProcess, Math.floor(((double) (System.currentTimeMillis() - start) / 1000) * 100) / 100);

		return this.cpeLookUp.getProductsToBeAddedToDatabase();
	}

	public Map<String, CpeGroup> loadCPEDict(int maxPages, int maxAttemptsPerPage) {
		return this.cpeLookUp.loadProductDict(maxPages, maxAttemptsPerPage);
	}

	public void loadCPEDict(Map<String, CpeGroup> productDict) {
		this.cpeLookUp.loadProductDict(productDict);
	}
}
