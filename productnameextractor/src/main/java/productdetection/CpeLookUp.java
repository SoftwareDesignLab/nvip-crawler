/ **
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
* /

package productdetection;

/**
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


import edu.rit.se.nvip.db.model.CpeEntry;
import edu.rit.se.nvip.db.model.CpeGroup;
import model.cpe.ProductItem;
import model.cpe.ProductVersion;
import opennlp.tools.tokenize.WhitespaceTokenizer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import versionmanager.VersionManager;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The CpeLookUp class is used to match CPEs to vulnerabilities after the NER Model has
 * derived product names and versions from each vulnerability.
 * 
 * @author Igor Khokhlov
 * @author Dylan Mulligan
 * @author Paul Vickers
 *
 */

public class CpeLookUp {

	private final static Logger logger = LogManager.getLogger(CpeLookUp.class);

	/**
	 * Inner class that maps a CPE Group with a score and can be sorted
	 */
	static class ScoredCpeGroup implements Comparable<ScoredCpeGroup> {
		private final float score;
		private final CpeGroup cpeGroup;

		/**
		 * Create new instance of CPEGroupFromMap, mapping CpeGroup to score
		 *
		 * @param score score of cpeGroup quality
		 * @param cpeGroup cpeGroup being scored
		 */
		public ScoredCpeGroup(float score, CpeGroup cpeGroup) {
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
		public int compareTo(ScoredCpeGroup o) {
			float compareScore = o.getScore();
			return Float.compare(compareScore, this.score);
		}
	}

	// Regex101: https://regex101.com/r/9uaTQb/1
	private static final Pattern CPE_PATTERN = Pattern.compile("cpe:2\\.3:[aho\\*\\-]:([^:]*):([^:]*):([^:]*):.*");

	// Set of generic standalone product names to blacklist from getting CPE groups matched
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

	// CPE items from CPE file
	private Map<String, CpeGroup> productDict = null;

	// HashSet to store how many unique cpe groups are identified
	private final Set<String> uniqueCPEGroups;

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
		this.productDict = productDict;
		logger.info("Successfully loaded CPE dictionary with {} entries", productDict.size());
	}

	/**
	 * Find CPE groups based on the given product's name and returns a list of scored
	 * CPE groups by how closely they match the product's name.
	 * 
	 * @param product product to search
	 *
	 * @return a list of found ScoredCpeGroup objects
	 */
	private ArrayList<ScoredCpeGroup> findCPEGroups(ProductItem product) {

		// Remove all symbols except letters, numbers, and space
		String productName = product.getName().toLowerCase();
		productName = productName.replaceAll("[^a-zA-Z0-9 ]", "");

		float maxScore = 0;
		CpeGroup chosenGroup;

		// Result list
		ArrayList<ScoredCpeGroup> groupsList = new ArrayList<>();

		// Ensures that generic product names do not get matched to CPE groups such as "security" or "server"
		String[] splitProductName = productName.split(" ");
		if(splitProductName.length == 1 && genericProductNames.contains(productName)){
			return groupsList;
		}

		// Iterate through all cpe groups
		for (Map.Entry<String, CpeGroup> entry : productDict.entrySet()) {

			// Split titles into array of strings
			String[] productNameWords = WhitespaceTokenizer.INSTANCE.tokenize(productName);
			String groupTitle = entry.getValue().getCommonTitle().toLowerCase().replaceAll("[^a-zA-Z0-9 ]", "");
			String[] groupTitlewords = WhitespaceTokenizer.INSTANCE.tokenize(groupTitle);

			// How many words matches
			int wordsMatched = 0;
			float score = 0;

			// How many words matches
			for (String productNameWord : productNameWords) {
				for (String groupTitleword : groupTitlewords) {
					if (productNameWord.equalsIgnoreCase(groupTitleword)) {
						wordsMatched++;
					}
				}
			}

			// Calculate matching score
			if (wordsMatched > 0) {
				if (productNameWords.length > groupTitlewords.length) {
					score = (float) wordsMatched / (float) productNameWords.length;
				} else {
					score = (float) wordsMatched / (float) groupTitlewords.length;
				}
			}

			// Add to the list if we have equal or greater than max score
			if (score >= maxScore && score > 0) {
				maxScore = score;
				chosenGroup = entry.getValue();
				groupsList.add(new ScoredCpeGroup(score, chosenGroup));
			}

		}

		// Sort in the descending order
		Collections.sort(groupsList);

		// Keep only best cpe groups
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
	 * @param selectedGroups resultant matching groups from the findCPEGroups method
	 * @param product product to search
	 * @return a list of found CPE ID Strings
	 */
	private ArrayList<String> getCPEIdsFromGroups(ArrayList<ScoredCpeGroup> selectedGroups, ProductItem product) {

		ArrayList<String> cpeIDs = new ArrayList<>();

		if (selectedGroups.size() == 0) {
			return null;
		}

		// If we don't have versions, generate cpe id without version
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

			for (ScoredCpeGroup selectedGroup : selectedGroups) {

				// Ensures that there are no duplicate entries
				HashSet<String> addedVersions = new HashSet<>();

				// If no version ranges available, break
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

						// If version is affected, create a CPE ID from it and add it to the list
						if(versionManager.isAffected(version)) {
							addedVersions.add(versionKey);
							matchesCounter++;
							String cpeID = "cpe:2.3:a:" + group.getGroupID() + ":" + versionKey + ":*:*:*:*:*:*:*";
							cpeIDs.add(cpeID);
							uniqueCPEGroups.add(selectedGroup.getCpeGroup().getGroupID() + product.hashCode());
						}
					} catch (IllegalArgumentException e) {
						logger.warn("Error parsing version string '{}': {}", versionKey, e.toString());
					}
				}

				// Look in the titles if did not find versions in the previous step
				if (matchesCounter == 0) {
					for (Map.Entry<String, CpeEntry> entry : groupVersions.entrySet()) {
						String entryTitle = entry.getValue().getTitle().toLowerCase();

						for (String versionWord : versionWords) {

							// If versionWord is not a valid version or cpe has already been made with that version, go next
							if(!VersionManager.isVersion(versionWord) || addedVersions.contains(versionWord)) continue;

							if (entryTitle.contains(versionWord)) {
								addedVersions.add(versionWord);
								matchesCounter++;
								String cpeID = "cpe:2.3:a:" + group.getGroupID() + ":" + versionWord + ":*:*:*:*:*:*:*";
								cpeIDs.add(cpeID);
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
								String cpeID = "cpe:2.3:a:" + group.getGroupID() + ":" + versionWord + ":*:*:*:*:*:*:*";
								cpeIDs.add(cpeID);
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
		ArrayList<ScoredCpeGroup> cpeGroups = findCPEGroups(product);
		return getCPEIdsFromGroups(cpeGroups, product);
	}

	/**
	 * Get CPE titles based on the given productName. If a CPE group contains
	 * the product name in its title, add it to the list of possible matching groups.
	 * 
	 * @param productName name of product to get titles for
	 *
	 * @return a list of found CPE titles
	 */
	public ArrayList<String> getCPETitles(String productName) {

		productName = productName.toLowerCase();
		productName = productName.replaceAll("[^a-zA-Z0-9 ]", "");

		ArrayList<String> groupsList = new ArrayList<>();

		// Go through each CPE group in the dict
		for (Map.Entry<String, CpeGroup> entry : productDict.entrySet()) {

			String groupTitle = entry.getValue().getCommonTitle().toLowerCase().replaceAll("[^a-zA-Z0-9 ]", "");

			// If the CPE group's title contains the product name, add it to the list
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
