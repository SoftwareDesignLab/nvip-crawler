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

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import model.Product;
import utils.*;
import opennlp.tools.tokenize.WhitespaceTokenizer;

/**
 * This class is to check is a software name in the CPE dictionary
 * 
 * @author Igor Khokhlov
 *
 */

public class CpeLookUp {
	private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36";
	private static final String BASE_NVD_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
	private static final int RESULTS_PER_PAGE = 10000; // Cannot query more than 10000 per page
	private final static ObjectMapper OM = new ObjectMapper();

	// Regex101: https://regex101.com/r/9uaTQb/1
	private static final Pattern CPE_PATTERN = Pattern.compile("cpe:2\\.3:[aho\\*\\-]:([^:]*):([^:]*):([^:]*):.*");
//	private static final String versionRegex = "(\\d+\\.(?:\\d+\\.)*\\d+)";

	/**
	 * A hash map of <CPE, Domain>
	 */
	private Map<String, CpeGroup> cpeMapFile = null; // CPE items from CPE file

	/**
	 * hash map of CPE to Product add list of products to database using
	 * map.values();
	 */
	private final Map<String, Product> productsToBeAddedToDatabase;
	private final static Logger logger = LogManager.getLogger(UtilHelper.class);


	/**
	 * Class that has CPE groups with matching score and can be sorted
	 */
	static class CPEGroupFromMap implements Comparable<CPEGroupFromMap> {
		private final float score;
		private final CpeGroup cpeGroup;

		public CPEGroupFromMap(float score, CpeGroup cpeGroup) {
			super();
			this.score = score;
			this.cpeGroup = cpeGroup;
		}

		public float getScore() {
			return score;
		}

		public CpeGroup getCpeGroup() {
			return cpeGroup;
		}

		@Override
		public int compareTo(CPEGroupFromMap o) {
			float compareScore = o.getScore();
			return Float.compare(compareScore, this.score);
		}
	}



	public CpeLookUp() {
		this.productsToBeAddedToDatabase = new HashMap<>();
	}

	public Map<String, Product> getProductsToBeAddedToDatabase() {
		return this.productsToBeAddedToDatabase;
	}

	public void addProductToDatabase(Product p) {
		this.productsToBeAddedToDatabase.put(p.getCpe(), p);
	}

	public void addProductsToDatabase(List<Product> products) {
		for (Product p : products) {
			addProductToDatabase(p);
		}
	}

	/**
	 * loads serialized CPE list of products from dictionary file in nvip data
	 *
	 * @return assigns list of product
	 */
	@SuppressWarnings({"unchecked", "rawtypes"})
	public void loadProductDict(int maxPages, int maxAttemptsPerPage) {
		// Init cpeMapFile
		cpeMapFile = new HashMap<>();

		// Collect CPE data from NVD API
		try {
			int index = 0;
			int attempts = 0;

			// Get raw data
			LinkedHashMap<String, ?> rawData = getNvdCpeData(index);

			// Extract results data
			int remainingResults = (int) rawData.get("totalResults");
			final int totalPages = (int) Math.ceil((double) remainingResults / RESULTS_PER_PAGE);
			while(remainingResults > 0 && attempts < maxAttemptsPerPage) {
				try {
					// Skip first query, as it was already done in order to get the totalResults number
					if(index > 0) {
						// Query next page
						rawData = getNvdCpeData(index);
					}

					// Extract product data
					final List<LinkedHashMap> rawProductData = (List<LinkedHashMap>) rawData.get("products");

					rawProductData.forEach(p -> {
						// Extract product map
						final LinkedHashMap<String, LinkedHashMap> product = (LinkedHashMap<String, LinkedHashMap>) p.get("cpe");

						// Extract cpe name
						final String fullCpeName = String.valueOf(product.get("cpeName"));

						// Extract cpe id
						final String cpeId = String.valueOf(product.get("cpeNameId"));

						// Match against CPE regex
						final Matcher m = CPE_PATTERN.matcher(fullCpeName);

						// Ensure CPE is formed correctly
						if(!m.find() || m.group(1) == null || m.group(2) == null || m.group(3) == null) {
							logger.warn("CPE '{}' skipped due to bad form", fullCpeName);
							return;
						}

						// Store matcher values
						final String vendorName = m.group(1);
						final String productName = m.group(2);
						final String version = m.group(3);

						// Build key
						final String key = String.join(":", vendorName, productName);

						// Add data to cpeMapFile
						CpeGroup value;
						// If key is not found, create new group and entry
						if(!cpeMapFile.containsKey(key)) {
							// Create group
							value = new CpeGroup(vendorName, productName);

							// Create & add entry to group
							value.addVersion(new CpeEntry(productName, version, cpeId));

							// Add group to cpeMapFile
							cpeMapFile.put(key, value);
						}
						// Update existing entries with versions
						else {
							// Get existing group from cpeMapFile
							final CpeGroup existingValue = cpeMapFile.get(key);

							// Get existing versions from group
							final Set<String> existingVersions = existingValue.getVersions().keySet();

							// If version does not already exist, add new entry
							if(!existingVersions.contains(version)) {
								// Create & add entry to group
								existingValue.addVersion(new CpeEntry(productName, version, cpeId));
							}
						}
					});

					// Reduce remaining results by number parsed
					remainingResults -= RESULTS_PER_PAGE;

					// Increment index
					index += RESULTS_PER_PAGE;
					// Sleep 2 sec between queries (adjust until we do not get 403 errors)
					Thread.sleep(2000);

					final int page = index / RESULTS_PER_PAGE;
					logger.info("Successfully loaded CPE dictionary page {}/{}", page, totalPages);
					if(page >= maxPages) {
						logger.warn("MAX_PAGES reached, the remaining {} pages will not be queried", totalPages - maxPages);
						break;
					}
				}
				// This block catches rate limiting errors, sleeps, then rethrows the error
				catch (InterruptedIOException e) {
					Thread.sleep(10000);
					throw e;
				} catch (Exception e) {
					logger.error("Error loading CPE dictionary page {}/{}, Attempt {}/{}: {}", index / RESULTS_PER_PAGE, totalPages, attempts + 1, maxAttemptsPerPage, e.toString());
					attempts++;
				}
			}

			logger.info("Loading product list is done!");
		} catch (Exception e) {
			logger.error("Error loading CPE dictionary: {}", e.toString());
		}
	}

	@SuppressWarnings("unchecked")
	private LinkedHashMap<String, ?> getNvdCpeData(int startIndex) throws JsonParseException, IOException {
		// Pagination parameter addition
		final String url = BASE_NVD_URL + String.format("?resultsPerPage=%s&startIndex=%s", RESULTS_PER_PAGE, startIndex);
		logger.info("Fetching product list from CPE dictionary at {}", url);

		// Query URL for contents (THIS WILL THROW AN IOException WHEN IT HITS A 403 RESPONSE)
		final String contents = getContentFromUrl(url);

		// Parse contents (if fails, will throw JsonParseException)
		return OM.readValue(contents, LinkedHashMap.class);
	}

	private static String getContentFromUrl(String url) throws InterruptedIOException {
		StringBuilder response = new StringBuilder();
		BufferedReader bufferedReader;

		try {
			URL urlObject = new URL(url);
			HttpURLConnection httpURLConnection = (HttpURLConnection) urlObject.openConnection();
			httpURLConnection.setRequestMethod("GET");
			httpURLConnection.setRequestProperty("User-Agent", USER_AGENT);
//			httpURLConnection.setRequestProperty("Accept-Encoding", "identity");

			// Rate limit protection
			if(httpURLConnection.getResponseCode() == 403) {
				throw new InterruptedIOException(String.format("URL '%s' responded with 403 - Forbidden. It is likely that rate limiting has been triggered.", url));
			}

			bufferedReader = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
			String inputLine;
			while ((inputLine = bufferedReader.readLine()) != null) {
				response.append(inputLine).append("\n");
			}
			bufferedReader.close();

		} catch(InterruptedIOException e) {
			throw e; // Rethrow
		} catch (IOException e) {
			logger.error(e.toString());
		}

		return response.toString();
	}

	/**
	 * Find CPE groups based on the product name
	 * 
	 * @param product product
	 *
	 * @return list of CPEgroupFromMap objects
	 */
	private ArrayList<CPEGroupFromMap> findCPEGroups(ProductItem product) {

		String productName = product.getName().toLowerCase();
		// remove all symbols except letters, numbers, and space
		productName = productName.replaceAll("[^a-zA-Z0-9 ]", "");

		float maxScore = 0;
		CpeGroup chosenGroup = null;

		// Result list
		ArrayList<CPEGroupFromMap> groupsList = new ArrayList<>();

		// iterate through all cpe groups
		for (Map.Entry<String, CpeGroup> entry : cpeMapFile.entrySet()) {

			// split titles into array of strings
			String[] productNameWords = WhitespaceTokenizer.INSTANCE.tokenize(productName);
			String groupTitle = entry.getValue().getCommonTitle().toLowerCase().replaceAll("[^a-zA-Z0-9 ]", "");
			String[] groupTitlewords = WhitespaceTokenizer.INSTANCE.tokenize(groupTitle);

			// how many words matches
			int wordsMatched = 0;
			float score = 0;

			// how many words matches
			for (String productNameWord : productNameWords) {
				for (String groupTitleword : groupTitlewords) {
					if (productNameWord.equalsIgnoreCase(groupTitleword)) {
						wordsMatched++;
					}
				}
			}

			// calculate matching score
			if (wordsMatched > 0) {
				if (productNameWords.length > groupTitlewords.length) {
					score = (float) wordsMatched / (float) productNameWords.length;
				} else {
					score = (float) wordsMatched / (float) groupTitlewords.length;
				}
			}

			// add to the list if we have equal or greater than max score
			if (score >= maxScore && score > 0) {
				maxScore = score;
				chosenGroup = entry.getValue();
				groupsList.add(new CPEGroupFromMap(score, chosenGroup));
			}

		}

		// sort in the descending order
		Collections.sort(groupsList);

		// keep only best cpe groups
		if (groupsList.size() > 0) {
			maxScore = groupsList.get(0).score;
			for (int i = 0; i < groupsList.size(); i++) {
				if (groupsList.get(i).getScore() < maxScore) {
					groupsList = new ArrayList<>(groupsList.subList(0, i));
					break;
				}
			}
		}

		return groupsList;
	}

	/**
	 * Finds IDs of the relevant CPE entries
	 * 
	 * @param product<CPEgroupFromMap> selectedGroups - result from the
	 *                                   findCPEgroups method
	 * @param selectedGroups                product
	 *
	 * @return list of CPEgroupFromMap objects
	 */ // TODO: Versions
	private ArrayList<String> getCPEIdsFromGroups(ArrayList<CPEGroupFromMap> selectedGroups, ProductItem product) {

		ArrayList<String> cpeIDs = new ArrayList<>();
		ArrayList<Product> productsToAdd = new ArrayList<>();

		if (selectedGroups.size() == 0) {
			return null;
		}

		// if we don't have versions, generate cpe id without version
		if (product.getVersions().size() == 0) {
			String cpeID = "cpe:2.3:a:" + selectedGroups.get(0).getCpeGroup().getGroupID() + ":*:*:*:*:*:*:*:*";
			cpeIDs.add(cpeID);
			productsToAdd.add(new Product(selectedGroups.get(0).getCpeGroup().getCommonTitle(), cpeID));
		} else {
			for (CPEGroupFromMap selectedGroup : selectedGroups) {

				HashMap<String, CpeEntry> groupVersions = selectedGroup.getCpeGroup().getVersions();

				for (int j = 0; j < product.getVersions().size(); j++) {
//					String[] versionWords = WhitespaceTokenizer.INSTANCE.tokenize(product.getVersions().get(j).toLowerCase());
					String[] versionWords = product.getVersions() // Get product versions
							.stream().map(String::toLowerCase) // Map each element toLowerCase
							.toArray(String[]::new); // Return elements in a String[]

					int matchesCounter = 0;

					// try to find version using a hashmap key
					for (String versionWord : versionWords) {
						CpeEntry cpeEntry = groupVersions.get(versionWord);

						if (cpeEntry != null) {
							matchesCounter++;
							cpeIDs.add(cpeEntry.getCpeID());
							productsToAdd.add(new Product(cpeEntry.getTitle(), cpeEntry.getCpeID()));
						}
					}

					// look in the titles if did not find versions in the previous step
					if (matchesCounter == 0) {
						for (Map.Entry<String, CpeEntry> entry : groupVersions.entrySet()) {
							String entryTitle = entry.getValue().getTitle().toLowerCase();

							for (String versionWord : versionWords) {
								if (entryTitle.contains(versionWord)) {
									cpeIDs.add(entry.getValue().getCpeID());
									productsToAdd.add(new Product(entry.getValue().getTitle(), entry.getValue().getCpeID()));
									break;
								}
							}
						}
					}

				}
			}

			// if did not find versions generate id without it
			if (cpeIDs.size() == 0) {
				String cpeID = "cpe:2.3:a:" + selectedGroups.get(0).getCpeGroup().getGroupID() + ":*:*:*:*:*:*:*:*";
				cpeIDs.add(cpeID);
				productsToAdd.add(new Product(selectedGroups.get(0).getCpeGroup().getCommonTitle(), cpeID));
			}
		}

		// Add found products
		addProductsToDatabase(productsToAdd);

		// Return CPEs of found products
		return cpeIDs;
	}

	/**
	 * Get CPE IDs based on the product
	 * 
	 * @param product product
	 *
	 * @return list of string with CPE IDs
	 */
	public ArrayList<String> getCPEIds(ProductItem product) {
		ArrayList<CPEGroupFromMap> cpeGroups = findCPEGroups(product);
		return getCPEIdsFromGroups(cpeGroups, product);
	}

	/**
	 * Get CPE titles based on the product name
	 * 
	 * @param productName productName
	 *
	 * @return list of CPE titles
	 */
	public ArrayList<String> getCPETitles(String productName) {

		productName = productName.toLowerCase();
		productName = productName.replaceAll("[^a-zA-Z0-9 ]", "");

		ArrayList<String> groupsList = new ArrayList<>();

		for (Map.Entry<String, CpeGroup> entry : cpeMapFile.entrySet()) {

			String groupTitle = entry.getValue().getCommonTitle().toLowerCase().replaceAll("[^a-zA-Z0-9 ]", "");

			if (groupTitle.contains(productName)) {
				groupsList.add(groupTitle);
			}
		}

		return groupsList;
	}

	public static String getVersionFromCPEid(String cpeID) {

		String version = null;

		String[] cpeIDelements = cpeID.split(":");
		// parse CPE id to elements
		if (cpeIDelements.length >= 11) {
			version = cpeIDelements[5];

		}
		return version;
	}

	public static String getVendorFromCPEid(String cpeID) {

		String vendor = null;

		// Match against CPE regex
		final Matcher m = CPE_PATTERN.matcher(cpeID);
		if(m.find()) vendor = m.group(1);
		else logger.warn("Could not match CPE String {}", cpeID);

		return vendor;
	}
}
