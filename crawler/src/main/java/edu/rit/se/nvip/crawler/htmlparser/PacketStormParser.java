/**
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
*/

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
package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import edu.rit.se.nvip.utils.UtilHelper;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Parse Web Pages for Packet Storm
 * (ex. https://packetstormsecurity.com/files/170988/Cisco-RV-Series-Authentication-Bypass-Command-Injection.html)
 *
 */
public class PacketStormParser extends AbstractCveParser {
	public static final String DOMAIN_NAME = "packetstorm";

	public PacketStormParser(){
		sourceDomainName = DOMAIN_NAME;
	}

	public PacketStormParser(String domainName) {
		sourceDomainName = domainName;
	}
	
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

	@Override
	public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		if (sSourceURL.contains(".html")) {
			return parseSingleHTMLPage(sSourceURL, sCVEContentHTML);
		} else {
			/**
			 *
			 * All pages have
			 * <dl class="file">
			 * and
			 * <dd class="cve">in them!
			 *
			 */
			return parseCVEListPage(sSourceURL, sCVEContentHTML);
		}

	}

	/**
	 * parse a packetstorm pages like
	 *
	 * https://packetstormsecurity.com/files/cve/CVE-2017-1000476
	 * https://packetstormsecurity.com/files/date/2004-01/
	 * https://packetstormsecurity.com/0307-advisories/
	 * https://packetstormsecurity.com/0309-exploits/
	 *
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	private List<RawVulnerability> parseCVEListPage(String sSourceURL, String sCVEContentHTML) {

		List<RawVulnerability> allVulns = new ArrayList<>();
		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.size() == 0)
			return allVulns;

		if (containsChineseChars(sCVEContentHTML))
			return allVulns;

		try {
			Document document = Jsoup.parse(sCVEContentHTML);

			String description;
			String publishDate;
			for (Element element : document.select("dl")) {

				// if no CVEs then continue!
				if (element.getElementsByClass("cve").size() == 0)
					continue;

				List<RawVulnerability> itemVulns = new ArrayList<>();

				// get unique CVEs in this list item
				uniqueCves = getCVEs(element.text());

				// title
				String listTitle = element.getElementsByIndexEquals(0).get(0).text();

				// get detail of the item
				Elements elements = element.getElementsByClass("detail");
				description = listTitle + "\n" + getDescription(elements);
				if (description.equals("\n"))
					continue;

				// get date
				elements = element.getElementsByClass("datetime");
				publishDate = getDate(sSourceURL, elements);

				for (String cve : uniqueCves)
					itemVulns.add(new RawVulnerability(sSourceURL, cve, publishDate, lastModifiedDate, description, getClass().getSimpleName()));

				allVulns.addAll(itemVulns);

			}
		} catch (Exception e) {
			logger.error("Error parsing: " + sSourceURL);
		}

		return allVulns;

	}

	/**
	 * get CVE description
	 * 
	 * @param elements
	 * @return
	 */
	private String getDescription(Elements elements) {
		String description = "";
		if (elements.isEmpty()) {
			//UtilHelper.addBadUrl(sSourceURL, "No description element found");
			return null;
		} else {
			for (Element e : elements)
				description += (e.text() + "\n");
		}

		return description;
	}

	/**
	 * get CVE date
	 * 
	 * @param sSourceURL
	 * @param elements
	 * @return
	 */
	private String getDate(String sSourceURL, Elements elements) {
		String publishDate = null;
		for (Element d : elements) {
			if (d.children().isEmpty())
				continue;
			Element a = d.child(0);
			if (a.tagName().equals("a"))
				try {
					publishDate = UtilHelper.longDateFormat.format(dateFormat_MMMddCommaYYYY.parse(a.text()));
				} catch (ParseException e) {
					logger.error("No publish date found at: " + sSourceURL);
				}
		}
		return publishDate;
	}

	/**
	 * parse a packetstorm page like:
	 * https://packetstormsecurity.com/files/105405/Mandriva-Linux-Security-Advisory-2011-138.html
	 * 
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	private List<RawVulnerability> parseSingleHTMLPage(String sSourceURL, String sCVEContentHTML) {
		List<RawVulnerability> vulns = new ArrayList<>();
		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.size() == 0)
			return vulns;

		if (containsChineseChars(sCVEContentHTML))
			return vulns;

		try {
			Document document = Jsoup.parse(sCVEContentHTML);

			String description;
			String publishDate;

			// gte description
			Elements descriptions = document.getElementsByClass("detail");
			description = getDescription(descriptions);
			if (description.equals(""))
				return vulns;

			// get date
			Elements dates = document.getElementsByClass("datetime");
			publishDate = getDate(sSourceURL, dates);

			for (String cve : uniqueCves)
				vulns.add(new RawVulnerability(sSourceURL, cve, publishDate, lastModifiedDate, description, getClass().getSimpleName()));

			/**
			 * get version from the remaining text
			 */
			document.select("br").append("\n");

			Elements codeTags = document.getElementsByTag("code");
			StringBuilder codeText = new StringBuilder();

			for (Element tag : codeTags)
				codeText.append(tag.text());

		} catch (Exception e) {
			logger.error("Error parsing: " + sSourceURL);
		}

		return vulns;

	}

}
