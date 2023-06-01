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
import java.net.SocketException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.SSLException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

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
	private static final int MAX_PAGES = 10;
	private static final int RESULTS_PER_PAGE = 10000; // Cannot query more than 10000 per page
	private final static ObjectMapper OM = new ObjectMapper();

	// Regex101: https://regex101.com/r/9uaTQb/1
	private static final Pattern CPE_REGEX = Pattern.compile("cpe:2\\.3:[aho\\*\\-]:([^:]*):([^:]*):([^:]*):.*");

	/**
	 * A hash map of <CPE, Domain>
	 */
	private Map<String, CpeGroup> cpeMapFile = null; // CPE items from CPE file

	/**
	 * hash map of CPE to Product add list of products to database using
	 * map.values();
	 */
	private final Map<String, Product> productsToBeAddedToDatabase;

	/** singleton instance of class */
	private static CpeLookUp cpeLookUp = null;

	private final String regexVersionInfo = "(?:(\\d+\\.(?:\\d+\\.)*\\d+))";

	static Logger logger = LogManager.getLogger(UtilHelper.class);

	/**
	 * Thread safe singleton implementation
	 * 
	 * @return
	 */
	public static synchronized CpeLookUp getInstance() {
		if (cpeLookUp == null)
			cpeLookUp = new CpeLookUp();

		return cpeLookUp;
	}

	private CpeLookUp() {
		productsToBeAddedToDatabase = new HashMap<>();
		loadProductDict();
	}

	public Map<String, Product> getProductsToBeAddedToDatabase() {
		return productsToBeAddedToDatabase;
	}

	public void addProductToDatabase(Product p) {
		productsToBeAddedToDatabase.put(p.getCpe(), p);
	}

	/**
	 * loads serialized CPE list of products from dictionary file in nvip data
	 *
	 * @return assigns list of product
	 */
	@SuppressWarnings({"unchecked", "rawtypes"})
	public void loadProductDict() {
		// Init cpeMapFile
		cpeMapFile = new HashMap<>();

		// Collect CPE data from NVD API
		try {
			int index = 0;

			// Get raw data
			LinkedHashMap<String, ?> rawData = getNvdCpeData(index);

			// Extract results data
			int remainingResults = (int) rawData.get("totalResults");
			final int totalPages = (int) Math.ceil((double) remainingResults / RESULTS_PER_PAGE);
			while(remainingResults > 0) {
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
						final Matcher m = CPE_REGEX.matcher(fullCpeName);

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

					final int page = index / RESULTS_PER_PAGE;
					logger.info("Successfully loaded CPE dictionary page {}/{}", page, totalPages);
					if(page >= MAX_PAGES) {
						logger.warn("MAX_PAGES reached, the remaining {} pages will not be queried", totalPages - MAX_PAGES);
						break;
					}
				} catch (Exception e) {
					logger.error("Error loading CPE dictionary @ page {}/{}: {}", index / RESULTS_PER_PAGE, totalPages, e.toString());
				}
			}

			logger.info("Loading product list is done!");
		} catch (Exception e) {
			logger.error("Error loading CPE dictionary: {}", e.toString());
		}
	}

	@SuppressWarnings("unchecked")
	private LinkedHashMap<String, ?> getNvdCpeData(int startIndex) throws IOException {
		// Pagination parameter addition
		final String url = BASE_NVD_URL + String.format("?resultsPerPage=%s&startIndex=%s", RESULTS_PER_PAGE, startIndex);
		logger.info("Fetching product list from CPE dictionary at {}", url);

		// Query URL
		return OM.readValue(getContentFromUrl(url), LinkedHashMap.class);
	}

	private static String getContentFromUrl(String url) {
		StringBuilder response = new StringBuilder();
		BufferedReader bufferedReader;

		try {
			URL urlObject = new URL(url);
			HttpURLConnection httpURLConnection = (HttpURLConnection) urlObject.openConnection();
			httpURLConnection.setRequestMethod("GET");
			httpURLConnection.setRequestProperty("User-Agent", USER_AGENT);
//			httpURLConnection.setRequestProperty("Accept-Encoding", "identity");

			bufferedReader = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
			String inputLine;
			while ((inputLine = bufferedReader.readLine()) != null) {
				response.append(inputLine + "\n");
			}
			bufferedReader.close();

		} catch (Exception e) {
			logger.error(e.toString());
		}

		return response.toString();
	}

	/**
	 * Processes and serializes CPE list of products from dictionary xml file
	 * 
	 * @param xmlfilename xmlfilename - CPE xml filename
	 * @param mapfilename mapfilename - taget filename
	 *
	 * @return assigns list of product
	 */
	static void cpeProcessing(String xmlfilename, String mapfilename) {

		logger.info("Loading product list from xml CPE dictionary");

		// Open CPE file
		File xmlFile = new File(xmlfilename);
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

		// Prepare final hashmap
		HashMap<String, CpeGroup> cpeMap = new HashMap<>();

		try {
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			org.w3c.dom.Document doc = dBuilder.parse(xmlFile);
			doc.getDocumentElement().normalize();

			logger.info("Root element: " + doc.getDocumentElement().getNodeName());
			NodeList nList = doc.getElementsByTagName("cpe-item");

			// Start parsing the CPE xml file
			for (int i = 0; i < nList.getLength(); i++) {
				NodeList children = nList.item(i).getChildNodes();
				String title = null;
				String cpeID = null;
				for (int j = 0; j < children.getLength(); j++) {
					Node child = children.item(j);
					if (child.getNodeName().equals("title")) {
						// get entry title
						title = child.getTextContent();
					} else if (child.getNodeName().equals("cpe-23:cpe23-item")) {
						// get entry id
						cpeID = child.getAttributes().getNamedItem("name").getNodeValue();
					}
					if (title != null && cpeID != null) {

						String[] cpeIDelements = cpeID.split(":");
						// parse CPE id to elements
						if (cpeIDelements.length >= 11) {
							String vendor = cpeIDelements[3];
							String name = cpeIDelements[4];
							String version = cpeIDelements[5];
							String update = cpeIDelements[6];
							String platform = cpeIDelements[10];

							CpeEntry cpeEntry = new CpeEntry(title, version, update, cpeID, platform);
							String groupID = vendor + ":" + name;
							CpeGroup group = cpeMap.get(groupID);

							if (group == null) {
								group = new CpeGroup(vendor, name);
								group.addVersion(cpeEntry);
								cpeMap.put(groupID, group);
							} else {
								group.addVersion(cpeEntry);
							}
						}

						break;
					}
				}
			}
		} catch (Exception e) {
			logger.error(e);
		}

		// Save map to the disk
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(mapfilename);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(cpeMap);
			oos.close();
			logger.info("Saving product list is done!");
		} catch (IOException e) {
			logger.error(e);
		}
	}

	/**
	 * Find CPE groups based on the product name
	 * 
	 * @param product product
	 *
	 * @return list of CPEgroupFromMap objects
	 */
	private ArrayList<CPEgroupFromMap> findCPEgroups(ProductItem product) {

		String productName = product.getName().toLowerCase();
		// remove all symbols except letters, numbers, and space
		productName = productName.replaceAll("[^a-zA-Z0-9 ]", "");

		float maxScore = 0;
		CpeGroup chosenGroup = null;

		// Result list
		ArrayList<CPEgroupFromMap> groupsList = new ArrayList<>();

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
				groupsList.add(new CPEgroupFromMap(score, chosenGroup));
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
	 */
	private ArrayList<String> getCPEidsFromGroups(ArrayList<CPEgroupFromMap> selectedGroups, ProductItem product) {

		ArrayList<String> cpeIDs = new ArrayList<>();

		if (selectedGroups.size() == 0) {
			return null;
		}

		// if we don't have versions, generate cpe id without version
		if (product.getVersions().size() == 0) {
			String cpeID = "cpe:2.3:a:" + selectedGroups.get(0).getCpeGroup().getGroupID() + ":*:*:*:*:*:*:*:*";
			cpeIDs.add(cpeID);
			addProductToDatabase(new Product(selectedGroups.get(0).getCpeGroup().getCommonTitle(), cpeID));
			return cpeIDs;
		}

		for (CPEgroupFromMap selectedGroup : selectedGroups) {

			HashMap<String, CpeEntry> groupVersions = selectedGroup.getCpeGroup().getVersions();

			for (int j = 0; j < product.getVersions().size(); j++) {
				String[] versionWords = WhitespaceTokenizer.INSTANCE.tokenize(product.getVersions().get(j).toLowerCase());

				int mathcesCounter = 0;

				// try to find version using a hashmap key
				for (String versionWord : versionWords) {
					CpeEntry cpeEntry = groupVersions.get(versionWord);

					if (cpeEntry != null) {
						mathcesCounter++;
						cpeIDs.add(cpeEntry.getCpeID());
						addProductToDatabase(new Product(cpeEntry.getTitle(), cpeEntry.getCpeID()));
					}
				}

				// look in the titles if did not find versions in the previous step
				if (mathcesCounter == 0) {
					for (Map.Entry<String, CpeEntry> entry : groupVersions.entrySet()) {
						String entryTitle = entry.getValue().getTitle().toLowerCase();

						for (String versionWord : versionWords) {
							if (entryTitle.contains(versionWord)) {
								cpeIDs.add(entry.getValue().getCpeID());
								addProductToDatabase(new Product(entry.getValue().getTitle(), entry.getValue().getCpeID()));
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
			addProductToDatabase(new Product(selectedGroups.get(0).getCpeGroup().getCommonTitle(), cpeID));
			return cpeIDs;
		}

		return cpeIDs;
	}

	/**
	 * Get CPE IDs based on the product
	 * 
	 * @param product product
	 *
	 * @return list of string with CPE IDs
	 */
	public ArrayList<String> getCPEids(ProductItem product) {
		ArrayList<CPEgroupFromMap> cpeGroups = findCPEgroups(product);
		return getCPEidsFromGroups(cpeGroups, product);
	}

	/**
	 * Given a product name string, return a matched CPE Product
	 * 
	 * @param domain
	 * @return
	 */
	public Product productFromDomain(String domain) {
		/**
		 * First create a ProductItem from String, then invoke getCPEids to derive CPEs.
		 */
		ProductItem pItem = new ProductItem(domain);
		ArrayList<String> cpeList = getCPEids(pItem);
		if (cpeList != null && cpeList.size() > 0)
			return new Product(domain, cpeList.get(0));

		return null;
	}

	/**
	 * Get CPE titles based on the product name
	 * 
	 * @param productName productName
	 *
	 * @return list of CPE titles
	 */
	public ArrayList<String> getCPEtitles(String productName) {

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
		final Matcher m = CPE_REGEX.matcher(cpeID);
		if(m.find()) vendor = m.group(2);
		else logger.warn("Could not match CPE String {}", cpeID);

		return vendor;
	}

	// Class that has CPE groups with matching score and can be sorted
	static class CPEgroupFromMap implements Comparable<CPEgroupFromMap> {
		private final float score;
		private final CpeGroup cpeGroup;

		public CPEgroupFromMap(float score, CpeGroup cpeGroup) {
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
		public int compareTo(CPEgroupFromMap o) {
			float compareScore = o.getScore();
			return Float.compare(compareScore, this.score);
		}
	}

	/**
	 * gets a product object based on a CPE
	 * 
	 * @param cpe CPE id to find
	 * @return Product with given cpe, null if CPE is not found in dictionary
	 */
	public Product productFromCpe(String cpe) {
		Product p = null;

		String[] cpeElements = cpe.split(":");
		String groupID = "";
		if (cpeElements.length > 5) {
			groupID = cpeElements[3] + ":" + cpeElements[4];
		} else {
			return null;
		}

		CpeGroup cpeGroup = cpeMapFile.get(groupID);

		if (cpeGroup != null) {
			CpeEntry cpeEntry = null;
			if (cpeElements.length > 6) {
				cpeEntry = cpeGroup.getVersions().get(cpeElements[5]);
			}

			if (cpeEntry != null) {
				p = new Product(cpeEntry.getTitle(), cpe);
			} else {
				p = new Product(cpeGroup.getCommonTitle(), cpe);
			}
		}

		if (p != null)
			addProductToDatabase(p);

		return p;
	}

	public List<String> productListFromDomain(String domain) {
		List<String> products = new ArrayList<>();
		for (CpeGroup cpeGroup : cpeMapFile.values()) {
			//Gives Product names without versions
			for (CpeEntry cpeEntry : cpeGroup.getVersions().values()) {
				products.add(cpeEntry.getTitle()); // Gives full product names WITH versions
			}
		}

		List<String> prodStrings = filterProducts(domain, products);
		if (prodStrings == null)
			return new ArrayList<>();
		return prodStrings;
	}

	private List<String> filterProducts(String domain, List<String> products) {
		List<String> curr = new ArrayList<>(products);

		Pattern pattern = Pattern.compile(regexVersionInfo);
		Matcher matcher = pattern.matcher(domain);
		if (matcher.find()) { // filter based on version first
			pattern = Pattern.compile(matcher.group());
			List<String> next = curr.stream().filter(pattern.asPredicate()).collect(Collectors.toList());
			if (next.size() > 0)
				curr = next;
		} else { // looking to match year
			Pattern yearPattern = Pattern.compile("[0-9]+");
			Matcher yearMatcher = yearPattern.matcher(domain);
			if (yearMatcher.find()) {
				yearPattern = Pattern.compile(yearMatcher.group());
				List<String> next = curr.stream().filter(yearPattern.asPredicate()).collect(Collectors.toList());
				if (next.size() > 0)
					curr = next;
			}
		}
		String[] domainArr = domain.split("[ -()]");
		for (int i = domainArr.length - 1; i >= 0; i--) {
			String word = domainArr[i];
			pattern = Pattern.compile("(" + word + ")");
			List<String> next = curr.stream().filter(pattern.asPredicate()).collect(Collectors.toList());
			if (next.size() == 1) {
				return next;
			} else if (next.size() == 0) {
				continue;
			}
			curr = next;
		}
		if (curr.size() == products.size())
			return null;
		return curr;
	}
	
	public Map<String, CpeGroup> getCpeMap(){
		return cpeMapFile;
	}

	public int getCpeKeyCount() {
		return cpeMapFile.size();
	}

	public int getCpeValueCount() {
		final AtomicInteger count = new AtomicInteger(0);
		cpeMapFile.values().forEach(g -> count.getAndAdd(g.getVersions().size()));
		return count.intValue();
	}

}
