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
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import edu.rit.se.nvip.utils.UtilHelper;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * Parse TalosIntelligence CVEs
 *
 * @author Ahmet Okutan
 *
 */
@Slf4j
public class TalosIntelligenceParser extends AbstractCveParser {
	public static final String DOMAIN_NAME = "talosintelligence";

	public TalosIntelligenceParser() {
		sourceDomainName = DOMAIN_NAME;
	}

	public TalosIntelligenceParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<RawVulnerability> vulnerabilities = new ArrayList<>();

		if (sSourceURL.contains("blog.talosintelligence.com") || sSourceURL.contains("/newsletters/"))
			return vulnerabilities;

		/**
		 * page contains CVE?
		 */
		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.size() == 0)
			return vulnerabilities;

		vulnerabilities = parseVulnPage(uniqueCves, sSourceURL, sCVEContentHTML);

		return vulnerabilities;
	}

	/**
	 * Parse pages like:
	 * https://talosintelligence.com/vulnerability_reports/TALOS-2020-1124
	 *
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	private List<RawVulnerability> parseVulnPage(Set<String> uniqueCves, String sSourceURL, String sCVEContentHTML) {
		List<RawVulnerability> vulnerabilities = new ArrayList<>();
		try {
			Document document = Jsoup.parse(sCVEContentHTML);

			StringBuilder description = new StringBuilder();
			String publishDate = null;
			StringBuilder platform = new StringBuilder();
			String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

			Elements allElements = document.select("h3, h5");

			for (Element element : allElements) {
				String text = element.text().toLowerCase();

				if (text.contains("summary")) {
					StringBuilder str = new StringBuilder();
					while (element.nextElementSibling() != null && element.nextElementSibling().tagName().equals("p")) {
						str.append(element.nextElementSibling().text());
						element = element.nextElementSibling();
					}
					description.append(str);
				}

				if (text.toLowerCase().contains("tested versions")) {
					StringBuilder str = new StringBuilder();
					if (element.nextElementSibling().tagName().equals("p")) {
						while (element.nextElementSibling() != null && element.nextElementSibling().tagName().equals("p")) {
							str.append(element.nextElementSibling().text());
							element = element.nextElementSibling();
						}
					} else {
						str = new StringBuilder(element.nextElementSibling().text());
					}
					platform.append(str);
				}

				if (text.contains("details")) {
					StringBuilder str = new StringBuilder();
					while (element.nextElementSibling() != null && element.nextElementSibling().tagName().equals("p")) {
						try {
							str.append(element.nextElementSibling().text());
							element = element.nextElementSibling();
						} catch (Exception ignored) {
						}
					}
					description.append(str);
				}

				if (text.contains("timeline")) {
					String str = "";
					try {
						if (element.nextElementSibling() != null && element.nextElementSibling().tagName().equals("p")) {
							str = element.nextElementSibling().text();
							List<String> dates = getDates(str);

							publishDate = dates.get(0);
							publishDate = UtilHelper.longDateFormat.format(dateFormat_yyyy_MM_dd.parse(publishDate));
						}
					} catch (Exception e) {
						log.error("Error parsing Timeline section at: " + sSourceURL);
					}
				}

			}
			if (description.toString().equals("")) return vulnerabilities;
			for (String cveId : uniqueCves)
				vulnerabilities.add(new RawVulnerability(sSourceURL, cveId, publishDate, lastModifiedDate, description.toString(), getClass().getSimpleName()));
		} catch (Exception e) {
			log.error("An error occurred while parsing TalosIntelligence URL: " + sSourceURL);
		}

		return vulnerabilities;
	}

	protected List<String> getDates(String text) {
		List<String> dates = new ArrayList<>();
		Pattern cvePattern = Pattern.compile(regexDateFormatNumeric);
		Matcher cveMatcher = cvePattern.matcher(text);
		while (cveMatcher.find())
			dates.add(cveMatcher.group());

		return dates;
	}

}
