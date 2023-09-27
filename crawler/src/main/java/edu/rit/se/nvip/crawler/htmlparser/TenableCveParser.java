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

import edu.rit.se.nvip.model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import edu.rit.se.nvip.utils.UtilHelper;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.time.LocalDate;

/**
 * Parse Teenable CVEs
 * 
 * @author axoeec
 *
 * Ex: https://www.tenable.com/cve/CVE-2022-21953
 */
public class TenableCveParser extends AbstractCveParser {

	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	public static final String DOMAIN_NAME = "tenable";

	public TenableCveParser() {
		sourceDomainName = DOMAIN_NAME;
	}

	public TenableCveParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

		if (sSourceURL.contains("/cve/newest") || sSourceURL.contains("/cve/updated"))
			return getCVEsFromSummaryPage(sSourceURL, sCVEContentHTML);

		List<RawVulnerability> vulns = new ArrayList<>();
		String description = "";

		Document doc = Jsoup.parse(sCVEContentHTML);
		String allText = doc.text();

		HashSet<String> uniqueCves = new HashSet<>();
		Pattern pattern = Pattern.compile(regexCVEID);
		Matcher matcher = pattern.matcher(allText);

		while (matcher.find())
			uniqueCves.add(matcher.group());
		if (uniqueCves.size() == 0) {
//			UtilHelper.addBadUrl(sSourceURL, "No CVE ID found");
			return vulns;
		}

		Elements descFields = doc.getElementsByAttributeValue("name", "description");
		if (descFields.size() == 1) {
			description = descFields.get(0).attr("content");
		} else {
//			UtilHelper.addBadUrl(sSourceURL, "Multiple or no description fields");
		}

		String publishDate = null;
		String updateDate = null;

		Elements strongs = doc.getElementsByTag("strong");
		for (Element s : strongs) {
			if (s.text().trim().equals("Published:")) {
				publishDate = s.parent().child(1).text();
			} else if (s.text().trim().equals("Updated:")) {
				updateDate = s.parent().child(1).text();
			}
		}

		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH);
		try {
			publishDate = UtilHelper.longDateFormat.format(dateFormat.parse(publishDate));
		} catch (ParseException | NullPointerException e) {
			logger.error("Failed to parse date on {}, format not known!", sSourceURL);
			publishDate = null;
		}

		Set<String> cpes = new HashSet<>();

		Elements allA = doc.getElementsByTag("a");
		for (Element a : allA) {
			if (a.text().contains("cpe:")) {
				cpes.add(a.text());
			}
		}

		if(publishDate == null){
			publishDate = LocalDate.now().toString();
		}
		if(updateDate == null){
			updateDate = LocalDate.now().toString();
		}

		for (String c : uniqueCves) {
			RawVulnerability vuln = new RawVulnerability(sSourceURL, c, publishDate, updateDate, description, getClass().getSimpleName());
			vulns.add(vuln);
		}

		return vulns;
	}

	private List<RawVulnerability> getCVEsFromSummaryPage(String sSourceURL, String sCVEContentHTML) {
		List<RawVulnerability> list = new ArrayList<>();
		String description = "";
		String cve;

		Document doc = Jsoup.parse(sCVEContentHTML);
		List<Element> tdList = doc.getElementsByClass("cve-id");
		String dateTimeNow = UtilHelper.longDateFormat.format(new Date());

		for (Element element : tdList) {
			cve = element.getElementsByTag("a").text();
			description = element.nextElementSibling().text();
			RawVulnerability vuln = new RawVulnerability(sSourceURL, cve, dateTimeNow, dateTimeNow, description, getClass().getSimpleName());
			list.add(vuln);
		}

		return list;

	}
}
