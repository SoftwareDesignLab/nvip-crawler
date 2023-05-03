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
package crawler.htmlparser;

import model.AffectedRelease;
import model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import utils.UtilHelper;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author axoeec
 *
 * Ex: https://www.kb.cert.org/vuls/id/434994
 */
public class KbCertCveParser extends AbstractCveParser  {

	public KbCertCveParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<RawVulnerability> vulnerabilities = new ArrayList<>();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
		Document document = Jsoup.parse(sCVEContentHTML);

		String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

		String publishDate = document.head().getElementsByAttributeValue("name", "published_at").attr("content");
		try {
			LocalDateTime published = LocalDateTime.parse(publishDate, formatter);
			publishDate = UtilHelper.longDateFormat.format(published);
		} catch (Exception pe) {
			pe.printStackTrace();
		}

		Elements myHTMLElements = document.select(":matchesOwn(" + regexAllCVERelatedContent + ")");
		String sCVEContent = myHTMLElements.text();
		String allText = document.text();

		String regexLastRevised = "(Last Revised|Updated): [0-9]+-[0-9]+-[0-9]+";
		Pattern lastRevisedPattern = Pattern.compile(regexLastRevised);
		Matcher matcher = lastRevisedPattern.matcher(allText);
		String lastModified;
		if (matcher.find()) {
			String[] splitLine = matcher.group().split(" ");
			lastModified = splitLine[splitLine.length - 1]; // format: yyyy-MM-dd
			try {
				LocalDateTime date = LocalDateTime.parse(lastModified, formatter);
				UtilHelper.longDateFormat.format(date);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		Pattern pattern = Pattern.compile(regexCVEID);
		matcher = pattern.matcher(sCVEContent);

		String description = getSingleDescription(document);

		Set<String> uniqueIds = new HashSet<>();
		while (matcher.find())
			uniqueIds.add(matcher.group());
		Set<String> descCves = new HashSet<>();
		matcher.reset(description);
		while (matcher.find())
			descCves.add(matcher.group());

		if (uniqueIds.size() < 1) {
			return null;
		}
		/**
		 * only one cveId on the page
		 */
		else if (uniqueIds.size() == 1 || descCves.size() <= 1) {
			Iterator<String> iterator = uniqueIds.iterator();
			while (iterator.hasNext()) {
				String cveId = iterator.next();
				RawVulnerability vuln = new RawVulnerability(sSourceURL, cveId, publishDate, lastModifiedDate, description);
				vulnerabilities.add(vuln);
			}
		}
		/**
		 * multiple cveIds on the page
		 */
		else {
			String[] sentences = description.split("[\\.:]");

			String currCve = null;
			StringBuilder currDesc = new StringBuilder();

			for (String sentence : sentences) {
				sentence = sentence.trim();
				matcher.reset(sentence);
				if (matcher.find()) {
					if (currCve != null) {
						String desc = currDesc.toString();
						RawVulnerability vuln = new RawVulnerability(sSourceURL, currCve, publishDate, lastModifiedDate, desc);
						vulnerabilities.add(vuln);
					}
					currCve = matcher.group();
					currDesc = new StringBuilder();
					currDesc.append(sentence + ".  ");
				} else {
					currDesc.append(sentence + ".");
				}
			}
			String desc = currDesc.toString();
			RawVulnerability vuln = new RawVulnerability(sSourceURL, currCve, publishDate, lastModifiedDate, desc);
			vulnerabilities.add(vuln);

		}

		return vulnerabilities;
	}

	/**
	 * gets description text of one page, if multiple cveIds on one page this
	 * returns the descriptions for all of them in one string
	 *
	 * @param document JavaSoup document of the page
	 * @return String of description
	 */
	private String getSingleDescription(Document document) {
		Elements h3s = document.getElementsByTag("h3");
		for (Element e : h3s) {
			if (e.text().trim().equalsIgnoreCase("description")) {
				// Start off at the header + 1 to get the first part of description
				int currIndex = e.elementSiblingIndex() + 1;
				Element parent = e.parent();
				// current index text
				StringBuilder currChildText = new StringBuilder(parent.child(currIndex).text().trim());
				// Multiple CVEs loop
				while (!parent.child(currIndex).tagName().equals("h3")) {
					currIndex++;
					Element thisChild = parent.child(currIndex);
					String thisChildText = thisChild.text().trim();
					currChildText.append(thisChildText);
				}
				return currChildText.toString();
			}
		}
		return null;
	}
}
