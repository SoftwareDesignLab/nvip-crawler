package edu.rit.se.nvip.patchfinder;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;

import org.eclipse.jgit.api.LsRemoteCommand;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import edu.rit.se.nvip.db.DatabaseHelper;

/**
 * Start patch finder for a given repository list (as .csv)
 * 
 * @author 15854
 *
 */
public class PatchFinderMain {

	private static DatabaseHelper db;
	private static final String[] ADDRESS_BASES = { "https://github.com/", "https://bitbucket.org/",
			"https://gitlab.com/" };

	/**
	 * Main method just for calling to find all patch URLs
	 * 
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {

		System.out.println("PatchFinder Started!");

		db = DatabaseHelper.getInstance();
		Map<String, ArrayList<String>> cpes = db.getCPEsByCVE();

		// Create github URLs based on CPEs for given CVEs
		for (Entry<String, ArrayList<String>> cpe : cpes.entrySet()) {
			parseURL(cpe);
		}

	}

	/**
	 * Gets a URL via a specified CVE and parses and tests
	 * 
	 * @throws IOException
	 */
	public static void parseURLByCVE(String cve_id) throws IOException {

		db = DatabaseHelper.getInstance();
		Map<String, ArrayList<String>> cpe = db.getCPEByCVE(cve_id);

		if (cpe.size() != 0) {
			for (Entry<String, ArrayList<String>> entry : cpe.entrySet()) {
				parseURL(entry);
			}
		}

	}

	/**
	 * Parses URL with github.com base and cpe keywords tests connection and inserts
	 * into DB if so.
	 * 
	 * @param cpe
	 * @throws IOException
	 */
	private static void parseURL(Entry<String, ArrayList<String>> cpe) throws IOException {

		String[] wordArr = cpe.getKey().split(":");

		if (!wordArr[3].equals("*")) {

			HashSet<String> addresses = initializeAddresses(wordArr[3]);

			for (String address : addresses) {

				String newAddress = "";

				if (!wordArr[4].equals("*")) {
					address += wordArr[4];
					newAddress = testConnection(address, wordArr[3], wordArr[4], cpe);
				} else {
					newAddress = testConnection(address, wordArr[3], null, cpe);
				}

				if (!newAddress.isEmpty()) {
					insertPatchURL(newAddress, cpe);
					break;
				} else {
					// advanceParseSearch(address, wordArr[3], wordArr[4], cpe);
				}

			}

		} else if (!wordArr[4].equals("*")) {

			for (String base : ADDRESS_BASES) {
				String newAddress = testConnection(base + wordArr[4], null, wordArr[4], cpe);
				if (!newAddress.isEmpty()) {
					insertPatchURL(newAddress, cpe);
					break;
				} else {
					// advanceParseSearch(newAddress, wordArr[3], wordArr[4], cpe);
				}
			}

		}

	}

	/**
	 * Inistializes the address set with additional addresses based on cpe keywords
	 */
	private static HashSet<String> initializeAddresses(String keyword) {
		HashSet<String> addresses = new HashSet<>();

		for (String base : ADDRESS_BASES) {
			addresses.add(base + keyword + "/");
			addresses.add(base + keyword + "_");
			addresses.add(base + keyword + "-");
			addresses.add(base + keyword);
		}

		return addresses;
	}

	/**
	 * Searches for all links within a comapanies github page to find the correct
	 * repo the cpe is correlated to. Uses keywords from cpe to validate and checks
	 * for git remote connection with found links
	 * 
	 * Uses jSoup framework
	 * 
	 * @param keyword1
	 * @param keyword2
	 * @param newURL
	 */
	private static String searchForRepos(String keyword1, String keyword2, String newURL) {
		System.out.println("Grabbing repos...");

		try {
			Document doc = Jsoup.connect(newURL).get();
			Elements links = doc.select("a[href]");

			for (Element link : links) {
				if (link.attr("href").contains("repositories")) {

					newURL = ADDRESS_BASES[0] + link.attr("href").substring(1);
					System.out.println("Repos located at: " + newURL);

					Document reposPage = Jsoup.connect(newURL).get();

					Elements repoLinks = reposPage.select("div.Box a[href]");

					for (Element repoLink : repoLinks) {
						if (!repoLink.attr("href").isEmpty()) {
							System.out.print(repoLink.attr("href"));
							newURL = ADDRESS_BASES[0] + repoLink.attr("href").substring(1);
							if (newURL.contains(keyword1) && newURL.contains(keyword2)) {
								LsRemoteCommand lsCmd = new LsRemoteCommand(null);

								lsCmd.setRemote(newURL + ".git");

								try {
									lsCmd.call();
									return newURL;
								} catch (Exception e) {
									System.out.println(e);
								}
							}
						}
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return "";

	}

	/**
	 * Performs an advanced search for the repo link(s) for a CPE using the Github
	 * search feature
	 * 
	 * @param address
	 * @param keyword1
	 * @param keyword2
	 * @param cpe
	 * @return
	 */
	private static ArrayList<String> advanceParseSearch(String address, String keyword1, String keyword2,
			Entry<String, ArrayList<String>> cpe) {
		return null;

	}

	/**
	 * Tests connetion of a crafted URL, If successful, insert in DB else, search
	 * for correct repo via github company page (Assuming the link directs to it for
	 * now)
	 * 
	 * @param address
	 * @param cpe
	 * @return
	 * @throws IOException
	 */
	private static String testConnection(String address, String keyword1, String keyword2,
			Entry<String, ArrayList<String>> cpe) throws IOException {

		URL url = new URL(address);
		HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
		int response = urlConnection.getResponseCode();

		// Check if the url leads to an actual GitHub repo
		// If so, push the source link into the DB
		if (response == HttpURLConnection.HTTP_OK) {
			urlConnection.connect();

			InputStream is = urlConnection.getInputStream();
			String newURL = urlConnection.getURL().toString();

			urlConnection.disconnect();
			is.close();

			LsRemoteCommand lsCmd = new LsRemoteCommand(null);

			lsCmd.setRemote(newURL + ".git");

			try {
				lsCmd.call();
				return newURL;
			} catch (Exception e) {
				System.out.println(e);
				return searchForRepos(keyword1, keyword2, newURL);
			}

		}
		return "";
	}

	/**
	 * Inserts a successfully connected Patch URL to the DB
	 */
	private static void insertPatchURL(String address, Entry<String, ArrayList<String>> cpe) {
		try {
			db.deletePatch(cpe.getValue().get(0));
			db.insertPatch(cpe.getValue().get(0), cpe.getValue().get(1), address, null, null);
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

}
