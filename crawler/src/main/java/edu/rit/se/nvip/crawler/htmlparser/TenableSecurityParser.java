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
package edu.rit.se.nvip.crawler.htmlparser;

// import edu.rit.se.nvip.model.Product;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.UtilHelper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.time.LocalDate;

/**
 *
 * @author axoeec
 *
 * Ex: <a href="https://www.tenable.com/security/research/tra-2023-5">Source</a>
 */
public class TenableSecurityParser extends AbstractCveParser {
	private static final Logger logger = LogManager.getLogger(TenableSecurityParser.class);

	public static final String DOMAIN_NAME = "tenable";

	public TenableSecurityParser() {
		sourceDomainName = DOMAIN_NAME;
	}

	public TenableSecurityParser(String domainName) {
		sourceDomainName = domainName;
	}
	
	@Override
	public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<RawVulnerability> vulns = new ArrayList<>();
		// List<Product> products = new ArrayList<>();
		boolean foundProducts = false;

		// If its the main research page, skip it since it has no descriptions
		if(sSourceURL.equals("https://www.tenable.com/security/research"))
			return vulns;

		Document doc = Jsoup.parse(sCVEContentHTML);

		Pattern pattern = Pattern.compile(regexCVEID);
		Matcher matcher = pattern.matcher("");

		Set<String> uniqueCves = new HashSet<>();

		Elements as = doc.getElementsByTag("a");
		for (Element e : as) {
			matcher.reset(e.text());
			if (matcher.find()) {
				uniqueCves.add(matcher.group());
			}
		}

		String desc = "";

		String releaseDateString = null;
		String updateDateString = null;

		Elements h3s = doc.getElementsByTag("h3");
		for (Element e : h3s) {
			if (e.text().trim().equals("Synopsis")) {
				desc = e.parent().child(1).text();
			} else if (e.text().trim().equals("Advisory Timeline")) {
				Elements dates = e.parent().getElementsByClass("field__item");
				if (dates.isEmpty()) {
					continue;
				}
				if(dates.size() == 1){
					releaseDateString = getDate(dates.get(0).text());
					updateDateString = getDate(dates.get(0).text());
					continue;
				}
				for (Element date : dates) {
					String dateText = date.text().toLowerCase();
					if (dateText.contains("release") || dateText.contains("published")) {
						releaseDateString = getDate(date.text());
					} else {
						updateDateString = getDate(date.text());
					}
				}
			} else if (e.text().toLowerCase().toLowerCase().equals("affected products")) {
//				products.addAll(getProducts(e.parent().getElementsByClass("field__items").get(0)));
				foundProducts = true;
			}
		}

		if (!foundProducts) {
			Elements labels = doc.getElementsByClass("field-label");
			for (Element label : labels) {
				if (label.text().toLowerCase().contains("affected products")) {
					Element prodElements = label.parent().child(1);
//					products.addAll(getProducts(prodElements));
				}
			}
		}

		if(releaseDateString == null){
			// logger.warn("WARNING: Release date null for {}", sSourceURL);
			releaseDateString = LocalDate.now().toString();
		}

		if(updateDateString == null){
			// logger.warn("WARNING: Update date is null for {}", sSourceURL);
			updateDateString = LocalDate.now().toString();
		}

		for (String cve : uniqueCves) {
			RawVulnerability vuln = new RawVulnerability(sSourceURL, cve, releaseDateString, updateDateString, desc, getClass().getSimpleName());
			vulns.add(vuln);
		}

		// for (Product p : products) {
		// 	Pattern versionPattern = Pattern.compile(regexVersionInfo);
		// 	Matcher versionMatcher = versionPattern.matcher(p.getDomain());
		// 	String version = (versionMatcher.find()) ? versionMatcher.group() : null;
		// }

		return vulns;
	}

	private String getDate(String given) {
		List<SimpleDateFormat> possibleFormats = new ArrayList<SimpleDateFormat>();
		possibleFormats.add(new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH));
		possibleFormats.add(new SimpleDateFormat("MMM d, yyyy", Locale.ENGLISH));
		possibleFormats.add(new SimpleDateFormat("MMM d yyyy", Locale.ENGLISH));
		possibleFormats.add(new SimpleDateFormat("MM/dd/yyyy", Locale.ENGLISH));
		for (SimpleDateFormat sdf : possibleFormats) {
			try {
				Date parsed = sdf.parse(given);
				if (parsed != null) {
					return UtilHelper.longDateFormat.format(parsed);
				}
			} catch (ParseException | NullPointerException e) {
				continue;
			}
		}
		return null;
	}

}
