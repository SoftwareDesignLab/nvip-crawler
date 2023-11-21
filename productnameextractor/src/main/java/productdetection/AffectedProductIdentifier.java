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

import model.cpe.CpeGroup;
import model.cpe.ProductItem;
import model.cpe.AffectedProduct;
import model.cve.CompositeVulnerability;
import opennlp.tools.tokenize.WhitespaceTokenizer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The AffectedProductIdentifier class controls the identification of specific
 * products (via version-specific CPEs) that are affected by known CVEs. The
 * resulting data is inserted into the affectedproducts table.
 *
 * @author axoeec
 * @author Dylan Mulligan
 * @author Paul Vickers
 *
 */

public class AffectedProductIdentifier {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private ProductDetector productDetector;
	private CpeLookUp cpeLookUp;
	private List<CompositeVulnerability> vulnList;
	private final int numThreads;

	/**
	 * Initialize the AffectedProductIdentifier with its own internal CpeLookup
	 * instance and a provided list of vulnerabilities to process for product identification
	 *
	 * @param vulnList list of vulnerabilities to process for product identification.
	 */
	public AffectedProductIdentifier(int numThreads, List<CompositeVulnerability> vulnList) {
		this.cpeLookUp = new CpeLookUp();
		this.numThreads = numThreads;
		this.vulnList = vulnList;
	}

	/**
	 * Releases held resources to free up memory
	 */
	public void releaseResources(){
		logger.info("Releasing affected product identifier from memory...");
		vulnList = null;
		cpeLookUp = null;
		if(productDetector != null){
			productDetector.unloadModels();
		}
		productDetector = null;
	}

	/**
	 * Sets the list of vulnerabilities to process. If the
	 * current list is not empty, clears it to process new list.
	 *
	 * @param vulnList list of vulnerabilities to use for product identification
	 */
	public void setVulnList(List<CompositeVulnerability> vulnList){
		if(!this.vulnList.isEmpty()) this.vulnList.clear();
		this.vulnList = vulnList;
	}

	/**
	 * Initializes the product detector instance
	 *
	 * @param resourceDir local resources directory
	 * @param nlpDir relative nlp directory (within resources)
	 * @param dataDir relative data directory (within resources)
	 */
	public void initializeProductDetector(String resourceDir, String nlpDir, String dataDir){
		try{
			productDetector = new ProductDetector(cpeLookUp, resourceDir, nlpDir, dataDir);
		} catch (IOException e){
			logger.error("Severe Error! Could not initialize the models for product name/version extraction! Skipping affected product identification step! {}", e.toString());
			System.exit(1);
		}
	}

	/**
	 * This method processes a given vulnerability (CVE) and attempts to map it against
	 * CPEs found in cpeLookUp.
	 *
	 * @param productNameDetector ProductDetector instance
	 * @param cpeLookUp CpeLookup instance
	 * @param vulnerability vulnerability being processed
	 */
	private int processVulnerability(
			ProductDetector productNameDetector,
			CpeLookUp cpeLookUp,
			CompositeVulnerability vulnerability
	) {
		String description = vulnerability.getDescription();

		if (description == null || description.length() == 0) {
//			counterOfBadDescriptionCVEs.getAndIncrement();
			return -2; // skip the ones without a description
		}

		// if a CVE did change, no need to extract products, assuming they are
		// already in DB!!
		if (vulnerability.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE) {
//			counterOfSkippedCVEs.getAndIncrement();
			return -1;
		}

//		counterOfProcessedCVEs.getAndIncrement();

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

			// Get list of existing affected products and ensure it is not null (should be empty list instead)
			final List<AffectedProduct> existingProducts = vulnerability.getAffectedProducts();
			assert existingProducts != null;

			// if no products found by crawlers, use AI/ML model to extract product/version
			// from text
			if (existingProducts.isEmpty()) {

				// Time measurement
				long startNERTime = System.currentTimeMillis();

				// get products from AI/ML model
				List<ProductItem> productList = productNameDetector.getProductItems(descriptionWords);

				long nerTime = System.currentTimeMillis() - startNERTime;
//				counterOfProcessedNERs.getAndIncrement();
//				totalNERTime.addAndGet(nerTime);

				int numProductsFound = 0;

				// map identified products/version to CPE
				for (ProductItem productItem : productList) {
					long startCPETime = System.currentTimeMillis();
					List<String> cpeIds = cpeLookUp.getCPEIds(productItem);
					long cpeTime = System.currentTimeMillis() - startCPETime;
//					totalCPETime.addAndGet(cpeTime);
//					counterOfProcessedCPEs.getAndIncrement();

					if (cpeIds == null || cpeIds.isEmpty()) {
//						numOfProductsNotMappedToCPE.getAndIncrement();
						logger.warn("Could not match CPEs for the predicted product name '{}'! | CVE-ID: {}", productItem.toString(), vulnerability.getCveId());
						continue;
					}

					// if CPE identified, add it as affected product
					for (String cpeID : cpeIds) {
						existingProducts.add(new AffectedProduct(vulnerability.getCveId(), cpeID, CpeLookUp.getNameFromCPEid(cpeID), CpeLookUp.getVersionFromCPEid(cpeID), CpeLookUp.getVendorFromCPEid(cpeID)));
//						numOfProductsMappedToCpe.getAndIncrement();
						numProductsFound++;
					}
				}

				logger.info("Found {} Affected Product(s) for {} in {} seconds", numProductsFound, vulnerability.getCveId(), (double) (System.currentTimeMillis() - startCVETime) / 1000);

				if(numProductsFound == 0) return -3;
				else return 0;
//					counterOfFailedCVEs.getAndIncrement();
			}

		} catch (Exception e) {
			logger.error("Error {} while extracting affected products! CVE: {}", e,
					vulnerability.toString());
			e.printStackTrace();
		}

//		totalCVETime.addAndGet(System.currentTimeMillis() - startCVETime);
		return -3;
	}

	/**
	 * This method drives the multithreaded identification process, driving CVEs pulled
	 * from the database through processVulnerability, in order to build a map of affected
	 * products.
	 *
	 * @return list of affected products
	 */
	public List<AffectedProduct> identifyAffectedProducts(CompositeVulnerability vuln) {
		logger.info("Starting to identify affected products for CVE '{}'", vuln.getCveId());

//		int totalCVEtoProcess = vulnList.size();
//		long start = System.currentTimeMillis();
//
//		AtomicInteger numOfProductsMappedToCpe = new AtomicInteger();
//		AtomicInteger numOfProductsNotMappedToCPE = new AtomicInteger();
//		AtomicInteger counterOfProcessedNERs = new AtomicInteger();
//		AtomicInteger counterOfProcessedCPEs = new AtomicInteger();
//		AtomicInteger counterOfFailedCVEs = new AtomicInteger();
//		AtomicInteger counterOfProcessedCVEs = new AtomicInteger();
//		AtomicInteger counterOfSkippedCVEs = new AtomicInteger();
//		AtomicInteger counterOfBadDescriptionCVEs = new AtomicInteger();
//		AtomicLong totalNERTime = new AtomicLong();
//		AtomicLong totalCPETime = new AtomicLong();
//		AtomicLong totalCVETime = new AtomicLong();
//
//		final BlockingQueue<Runnable> workQueue = new ArrayBlockingQueue<>(vulnList.size());
//
//		final ThreadPoolExecutor executor = new ThreadPoolExecutor(
//				numThreads,
//				numThreads,
//				15,
//				TimeUnit.SECONDS,
//				workQueue
//		);
//
//		executor.prestartAllCoreThreads();
//
//		for (int i = 0; i < vulnList.size(); i++) {
//			if(i >= totalCVEtoProcess){
//				break;
//			}
//			CompositeVulnerability vulnerability = vulnList.get(i);
//			try {
//				if(!workQueue.offer(() -> processVulnerability(
//						productDetector,
//						cpeLookUp,
//						vulnerability,
//						counterOfBadDescriptionCVEs,
//						counterOfSkippedCVEs,
//						counterOfProcessedCVEs,
//						counterOfProcessedNERs,
//						counterOfProcessedCPEs,
//						counterOfFailedCVEs,
//						numOfProductsNotMappedToCPE,
//						numOfProductsMappedToCpe,
//						totalNERTime,
//						totalCPETime,
//						totalCVETime
//				))) throw new Exception();
//			} catch (Exception e) {
//				logger.error("Failed to add {} to the work queue: {}", vulnerability.getCveId(), e.toString());
//				totalCVEtoProcess--;
//				counterOfSkippedCVEs.incrementAndGet();
//			}
//		}
//
//		executor.shutdown();

//		final int timeout = 15;
//		final int logFrequency = 60;
//		long secondsWaiting = 0;
//		int numCVEsProcessed = 0;
//		int lastNumCVEs = totalCVEtoProcess;
//		try {
//			while(!executor.awaitTermination(timeout, TimeUnit.SECONDS)) {
//				secondsWaiting += timeout;
//
//				// Every minute, log a progress update
//				if(secondsWaiting % logFrequency == 0) {
//
//					// Determine number of CVEs processed
//					final int currNumCVEs = workQueue.size(); // Current number of remaining CVEs
//					final int deltaNumCVEs = lastNumCVEs - currNumCVEs; // Change in CVEs since last progress update
//
//					// Sum number processed
//					numCVEsProcessed += deltaNumCVEs;
//
//					// Calculate rate, avg rate, and remaining time
//					final double rate = (double) deltaNumCVEs / logFrequency; // CVEs/sec
//					final double avgRate = (double) numCVEsProcessed / secondsWaiting; // CVEs/sec
//					final double remainingAvgTime = currNumCVEs / rate; // CVEs / CVEs/sec = remaining seconds
//
//					// Log stats
//					logger.info(
//							"{} out of {} CVEs processed (SP: {} CVEs/sec | AVG SP: {} CVEs/sec | Est time remaining: {} minutes ({} seconds))...",
//							totalCVEtoProcess - currNumCVEs,
//							totalCVEtoProcess,
//							Math.floor(rate * 100) / 100,
//							Math.floor(avgRate * 100) / 100,
//							Math.floor(remainingAvgTime / 60 * 100) / 100,
//							Math.floor(remainingAvgTime * 100) / 100
//					);
//
//					// Update lastNumCVEs
//					lastNumCVEs = currNumCVEs;
//				}
//			}
//		} catch (Exception ex) {
//			logger.error("Product extraction failed: {}", ex.toString());
//			List<Runnable> remainingTasks = executor.shutdownNow();
//			logger.error("{} tasks not executed", remainingTasks.size());
//		}

//		logger.info("Successfully processed {} out of {} CVEs!", counterOfProcessedCVEs, totalCVEtoProcess);
//		logger.info("Found products for {} CVE(s) | Failed to find products for {} CVE(s) | Skipped {} CVE(s)",
//				counterOfProcessedCVEs.get() - counterOfFailedCVEs.get(), counterOfFailedCVEs, counterOfSkippedCVEs);
//
//		AtomicInteger count = new AtomicInteger();
//		vulnList.stream().map(v -> v.getAffectedProducts().size()).forEach(count::addAndGet);
//		logger.info("Found {} affected products ({} unique excluding versions) from {} CVEs in {} seconds", count, cpeLookUp.getUniqueCPECount(), totalCVEtoProcess, Math.floor(((double) (System.currentTimeMillis() - start) / 1000) * 100) / 100);

		final int result = processVulnerability(productDetector, cpeLookUp, vuln);

		List<AffectedProduct> affectedProducts = new ArrayList<>();
		if (vuln.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE)
			affectedProducts.addAll(vuln.getAffectedProducts());

		return affectedProducts;
	}

	/**
	 * Instructs the internal instance of cpeLookUp to load the given CPE dictionary.
	 *
	 * @param productDict CPE dictionary to load
	 */
	public void loadProductDict(Map<String, CpeGroup> productDict) {
		cpeLookUp.loadProductDict(productDict);
	}
}
