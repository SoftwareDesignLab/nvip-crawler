package edu.rit.se.nvip; /**
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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.rit.se.nvip.model.cpe.*;
import opennlp.tools.tokenize.WhitespaceTokenizer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InterruptedIOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class is to check is a software name in the CPE dictionary
 * 
 * @author Igor Khokhlov
 * @author Dylan Mulligan
 * @author Paul Vickers
 *
 */

public class CpeLookUp {
	private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36";
	private static final String BASE_NVD_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
	private static final int RESULTS_PER_PAGE = 10000; // Cannot query more than 10000 per page
	private final static ObjectMapper OM = new ObjectMapper();

	// Regex101: https://regex101.com/r/9uaTQb/1
	private static final Pattern CPE_PATTERN = Pattern.compile("cpe:2\\.3:[aho\\*\\-]:([^:]*):([^:]*):([^:]*):.*");

	//Set of generic standalone product names to blacklist from getting CPE groups matched
	private static final HashSet<String> genericProductNames;
	static{
		genericProductNames = new HashSet<>();
		genericProductNames.add("security");
		genericProductNames.add("hub");
		genericProductNames.add("server");
		genericProductNames.add("store");
		genericProductNames.add("statistics");
		genericProductNames.add("view");
		genericProductNames.add("remote");
		genericProductNames.add("notification");
		genericProductNames.add("scripting");
		genericProductNames.add("agent");
		genericProductNames.add("generator");
		genericProductNames.add("request");
		genericProductNames.add("update");
		genericProductNames.add("network");
		genericProductNames.add("access");
		genericProductNames.add("image");
		genericProductNames.add("business");
		genericProductNames.add("accessibility");
		genericProductNames.add("release");
		genericProductNames.add("mail");
		genericProductNames.add("mobile");
		genericProductNames.add("data");
		genericProductNames.add("service");
		genericProductNames.add("runtime");
		genericProductNames.add("date");
		genericProductNames.add("safety");
		genericProductNames.add("account");
		genericProductNames.add("web");
		genericProductNames.add("driver");
	}

	//CPE items from CPE file
	private Map<String, CpeGroup> cpeMapFile = null;

	//HashSet to store how many unique cpe groups are identified
	private final Set<String> uniqueCPEGroups;

	private final static Logger logger = LogManager.getLogger(CpeLookUp.class);

	/**
	 * Class that has CPE groups with matching score and can be sorted
	 */
	static class CPEGroupFromMap implements Comparable<CPEGroupFromMap> {
		private final float score;
		private final CpeGroup cpeGroup;

		/**
		 * Create new instance of CPEGroupFromMap, mapping CpeGroup to score
		 *
		 * @param score score of cpeGroup quality TODO: what is this score based on?
		 * @param cpeGroup cpeGroup being scored
		 */
		public CPEGroupFromMap(float score, CpeGroup cpeGroup) {
			super();
			this.score = score;
			this.cpeGroup = cpeGroup;
		}


		/**
		 * @return the CpeGroup's score
		 */
		public float getScore() {
			return score;
		}

		/**
		 * @return the CpeGroup
		 */
		public CpeGroup getCpeGroup() {
			return cpeGroup;
		}

		/**
		 * Compare this.score to o.score.
		 *
		 * @param o the object to be compared.
		 * @return -1 | 0 | 1 based on score comparison
		 */
		@Override
		public int compareTo(CPEGroupFromMap o) {
			float compareScore = o.getScore();
			return Float.compare(compareScore, this.score);
		}
	}

	/**
	 * Create new instance of CpeLookUp
	 */
	public CpeLookUp() {
		uniqueCPEGroups = new HashSet<>();
	}

	// Returns number of unique CPE Groups that have been identified
	public int getUniqueCPECount(){
		return uniqueCPEGroups.size();
	}

	/**
	 * Loads a CPE dictionary of products from file
	 */
	public void loadProductDict(Map<String, CpeGroup> productDict) {
		this.cpeMapFile = productDict;
		logger.info("Successfully loaded CPE dictionary with {} entries", productDict.size());
	}

	/**
	 * Compiles a CPE dictionary of products from querying NVD's CPE API
	 *
	 * @return a map of loaded CpeGroup objects
	 */
	@SuppressWarnings({"unchecked", "rawtypes"})
	public Map<String, CpeGroup> queryProductDict(int maxPages, int maxAttemptsPerPage) {
		// If maxPages is set to 0, no limit on pages
		if(maxPages == 0) maxPages = Integer.MAX_VALUE;
		// If maxAttemptsPerPage is set to 0, no limit on attempts
		if(maxAttemptsPerPage == 0) maxAttemptsPerPage = Integer.MAX_VALUE;

		// Init cpeMapFile
		final HashMap<String, CpeGroup> productDict = new HashMap<>();

		// Collect CPE data from NVD API
		try {
			int index = 0;
			int attempts = 0;

			// Get raw data
			LinkedHashMap<String, ?> rawData = getNvdCpeData(index);

			// Extract results data
			int remainingResults = (int) rawData.get("totalResults");
			final int totalPages = (int) Math.ceil((double) remainingResults / RESULTS_PER_PAGE);
			while(remainingResults > 0) {
				// Skip page after it has reach max attempts
				if(attempts >= maxAttemptsPerPage) {
					// Reduce remaining results by number parsed
					remainingResults -= RESULTS_PER_PAGE;
					// Increment index
					index += RESULTS_PER_PAGE;
					// Sleep 2 sec between queries (adjust until we do not get 403 errors)
					Thread.sleep(2500);
					// Reset attempt count
					attempts = 0;
				}
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
						if(!productDict.containsKey(key)) {
							// Create group
							value = new CpeGroup(vendorName, productName);

							// Create & add entry to group
							value.addVersion(new CpeEntry(productName, version, cpeId));

							// Add group to cpeMapFile
							productDict.put(key, value);
						}
						// Update existing entries with versions
						else {
							// Get existing group from cpeMapFile
							final CpeGroup existingValue = productDict.get(key);

							// Get existing versions from group
							final Set<String> existingVersions = existingValue.getVersions().keySet();

							// If version does not already exist, add new entry
							if(!existingVersions.contains(version)) {
								// Create & add entry to group
								existingValue.addVersion(new CpeEntry(productName, version, cpeId));
							}
						}
					});

					final int page = 1 + (index / RESULTS_PER_PAGE);

					// Reduce remaining results by number parsed
					remainingResults -= RESULTS_PER_PAGE;
					// Increment index
					index += RESULTS_PER_PAGE;
					// Sleep 2.5 sec between queries (adjust until we do not get 403 errors)
					Thread.sleep(2500);
					// Reset attempt count
					attempts = 0;

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
					logger.error("Error loading CPE dictionary page {}/{}, Attempt {}/{}: {}", (index / RESULTS_PER_PAGE) + 1, totalPages, attempts + 1, maxAttemptsPerPage, e.toString());
					attempts++;
				}
			}

			logger.info("Loading product list is done!");
		} catch (Exception e) {
			logger.error("Error loading CPE dictionary: {}", e.toString());
		}

		return productDict;
	}

	/**
	 * Queries NVD with the given startIndex parameter, returning the raw mapped data
	 *
	 * @param startIndex offset for query
	 * @return raw mapped data
	 * @throws JsonParseException if an exception occurs while attempting to parse the page contents
	 * @throws IOException if an exception occurs while attempting to retrieve the page contents
	 */
	@SuppressWarnings("unchecked")
	private LinkedHashMap<String, ?> getNvdCpeData(int startIndex) throws JsonParseException, IOException {
		// Pagination parameter addition
		final String url = BASE_NVD_URL + String.format("?resultsPerPage=%s&startIndex=%s", RESULTS_PER_PAGE, startIndex);
		logger.info("Fetching product list from CPE dictionary at {}", url);

		// Query URL for contents (THIS WILL THROW AN IOException WHEN IT HITS A 403 RESPONSE)
		final String contents = getContentFromUrl(url);

		// Parse contents (if fails, will throw JsonParseException)
		try {
			return OM.readValue(contents, LinkedHashMap.class);
		} catch (JsonParseException e) {
			throw e;
		}
	}

	/**
	 * Queries and gets the contents of a given url, returning the result as a String.
	 *
	 * @param url url to query
	 * @return String contents of url
	 * @throws IOException if an error occurs while parsing the given url
	 */
	private static String getContentFromUrl(String url) throws IOException {
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
	 * Find CPE groups based on the given product's name
	 * 
	 * @param product product to search
	 *
	 * @return a list of found CPEGroupFromMap objects
	 */
	private ArrayList<CPEGroupFromMap> findCPEGroups(ProductItem product) {

		String productName = product.getName().toLowerCase();
		// remove all symbols except letters, numbers, and space
		productName = productName.replaceAll("[^a-zA-Z0-9 ]", "");

		float maxScore = 0;
		CpeGroup chosenGroup = null;

		// Result list
		ArrayList<CPEGroupFromMap> groupsList = new ArrayList<>();

		//Ensures that generic product names do not get matched to CPE groups such as "security" or "server"
		String[] splitProductName = productName.split(" ");
		if(splitProductName.length == 1 && genericProductNames.contains(productName)){
			return groupsList;
		}

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
	 * Finds CPE IDs of the relevant CPE entries by matching affected versions of the product to versions
	 * stored in the selected CPE groups
	 * 
	 * @param selectedGroups result from the findCPEGroups method
	 * @param product product to search
	 * @return a list of found CPE ID Strings
	 */
	private ArrayList<String> getCPEIdsFromGroups(ArrayList<CPEGroupFromMap> selectedGroups, ProductItem product) {

		ArrayList<String> cpeIDs = new ArrayList<>();

		if (selectedGroups.size() == 0) {
			return null;
		}

		// if we don't have versions, generate cpe id without version
		if (product.getVersions().size() == 0) {
			String cpeName = "cpe:2.3:a:" + selectedGroups.get(0).getCpeGroup().getGroupID() + ":*:*:*:*:*:*:*:*";
			cpeIDs.add(cpeName);
		} else {
			// Get raw version words array
			String[] versionWords = product.getVersions() // Get product versions
					.stream().map(String::toLowerCase) // Map each element toLowerCase
					.toArray(String[]::new); // Return elements in a String[]

			//Instantiate new VersionManager
			VersionManager versionManager = new VersionManager();

			// Process non-specific versions into enumerated ranges
			// [ "1.2.2", "through", "1.3", "1.5", "before", "1.8.9" ]
			// [ "1.2.2", "1.2.3", ... "1.3", 1.5, "1.8.0", ... "1.8.9" ]
			versionManager.processVersions(versionWords);

			for (CPEGroupFromMap selectedGroup : selectedGroups) {

				//Ensures that there are no duplicate entries
				HashSet<String> addedVersions = new HashSet<>();

				//If no version ranges available, break
				if(versionManager.getVersionRanges().size() == 0){
					break;
				}

				// Get versions from group
				final CpeGroup group = selectedGroup.getCpeGroup();
				final HashMap<String, CpeEntry> groupVersions = group.getVersions();

				// Counter for matching versions
				int matchesCounter = 0;

				// Iterate over groupVersions map to check for affected CpeEntries
				for (Map.Entry<String, CpeEntry> gv : groupVersions.entrySet()) {
					final String versionKey = gv.getKey();

					// If versionKey is not a valid version or cpe has already been made with that version, go next
					if(!VersionManager.isVersion(versionKey) || addedVersions.contains(versionKey)) continue;

					try {
						final ProductVersion version = new ProductVersion(versionKey);
						if(versionManager.isAffected(version)) {
							addedVersions.add(versionKey);
							matchesCounter++;
							String cpeName = "cpe:2.3:a:" + group.getGroupID() + ":" + versionKey + ":*:*:*:*:*:*:*";
							cpeIDs.add(cpeName);
							uniqueCPEGroups.add(selectedGroup.getCpeGroup().getGroupID() + product.hashCode());
						}
					} catch (IllegalArgumentException e) {
						logger.warn("Error parsing version string '{}': {}", versionKey, e.toString());
					}
				}

				// look in the titles if did not find versions in the previous step
				if (matchesCounter == 0) {
					for (Map.Entry<String, CpeEntry> entry : groupVersions.entrySet()) {
						String entryTitle = entry.getValue().getTitle().toLowerCase();

						for (String versionWord : versionWords) {

							// If versionWord is not a valid version or cpe has already been made with that version, go next
							if(!VersionManager.isVersion(versionWord) || addedVersions.contains(versionWord)) continue;

							if (entryTitle.contains(versionWord)) {
								addedVersions.add(versionWord);
								matchesCounter++;
								String cpeName = "cpe:2.3:a:" + group.getGroupID() + ":" + versionWord + ":*:*:*:*:*:*:*";
								cpeIDs.add(cpeName);
								uniqueCPEGroups.add(selectedGroup.getCpeGroup().getGroupID() + product.hashCode());
							}
						}
					}
				}

				//If we did not find versions in titles, try to find the version from the versions list
				if (matchesCounter == 0) {

					//Find the version from the versions list
					for (String versionWord : versionWords) {

						// If versionWord is not a valid version or cpe has already been made with that version, go next
						if (!VersionManager.isVersion(versionWord) || addedVersions.contains(versionWord)) continue;

						// If versionWord is a valid version, check if it is affected
						try {
							final ProductVersion version = new ProductVersion(versionWord);
							if (versionManager.isAffected(version)) {
								addedVersions.add(versionWord);
								matchesCounter++;
								String cpeName = "cpe:2.3:a:" + group.getGroupID() + ":" + versionWord + ":*:*:*:*:*:*:*";
								cpeIDs.add(cpeName);
								uniqueCPEGroups.add(selectedGroup.getCpeGroup().getGroupID() + product.hashCode());
							}
						} catch (IllegalArgumentException e) {
							logger.warn("Error parsing version string '{}': {}", versionWord, e.toString());
						}
					}
				}
			}

			// if did not find versions generate id without it
			if (cpeIDs.size() == 0) {
				String cpeID = "cpe:2.3:a:" + selectedGroups.get(0).getCpeGroup().getGroupID() + ":*:*:*:*:*:*:*:*";
				cpeIDs.add(cpeID);
				uniqueCPEGroups.add(selectedGroups.get(0).getCpeGroup().getGroupID() + product.hashCode());
			}
		}

		// Return CPEs of found products
		return cpeIDs;
	}

	/**
	 * Get CPE IDs based on the given product
	 * 
	 * @param product product to search
	 *
	 * @return a list of found CPE ID Strings
	 */
	public ArrayList<String> getCPEIds(ProductItem product) {
		ArrayList<CPEGroupFromMap> cpeGroups = findCPEGroups(product);
		return getCPEIdsFromGroups(cpeGroups, product);
	}

	/**
	 * Get CPE titles based on the given productName
	 * 
	 * @param productName name of product to get titles for
	 *
	 * @return a list of found CPE titles
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

	/**
	 * Gets the version component of a given CPE ID
	 *
	 * @param cpeID CPE ID to search
	 * @return found version String
	 */
	public static String getVersionFromCPEid(String cpeID) {
		String version = null;

		// Match against CPE regex
		final Matcher m = CPE_PATTERN.matcher(cpeID);
		if(m.find()) version = m.group(3);
		else logger.warn("Could not match CPE String {}", cpeID);

		return version;
	}

	/**
	 * Gets the name component of a given CPE ID
	 *
	 * @param cpeID CPE ID to search
	 * @return found name String
	 */
	public static String getNameFromCPEid(String cpeID) {
		String name = null;

		// Match against CPE regex
		final Matcher m = CPE_PATTERN.matcher(cpeID);
		if(m.find()) name = m.group(2);
		else logger.warn("Could not match CPE String {}", cpeID);

		return name;
	}

	/**
	 * Gets the vendor component of a given CPE ID
	 *
	 * @param cpeID CPE ID to search
	 * @return found vendor String
	 */
	public static String getVendorFromCPEid(String cpeID) {
		String vendor = null;

		// Match against CPE regex
		final Matcher m = CPE_PATTERN.matcher(cpeID);
		if(m.find()) vendor = m.group(1);
		else logger.warn("Could not match CPE String {}", cpeID);

		return vendor;
	}
}
