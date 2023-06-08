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
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import edu.rit.se.nvip.model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

/**
 * 
 * Generic Cve parser for NVIP PoC that splits into
 * different parser strategies based on page given
 *
 */
public class GenericCveParser extends AbstractCveParser  {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	/**
	 * Parser strategy interface for Generic Parsing
	 * based on strategy selected. See: app.diagrams.net/#G1ZhVaJu0XKpyKtDhr2uqTQVVWg-X07XC1
	 * By default ParseCVEDescription is used on entire page
	 */
	private ParserStrategy parserStrategy = null;
	
	public GenericCveParser(String domainName) {
		sourceDomainName = domainName;
	}

	public GenericCveParser(String domainName, ParserStrategy parserStrategy) {
		sourceDomainName = domainName;
		this.parserStrategy = parserStrategy;
	}

	protected ParserStrategy chooseParserStrategy(String sCVEContentHTML) {
		// pull HTML
		Document doc = Jsoup.parse(sCVEContentHTML);
		// check for strategy conditions
		// --- check for table
		Elements cveTables = doc.select("table:contains(CVE), thead:contains(CVE), tbody:contains(CVE)");
		if (cveTables.size() > 0 && cveTables.size() < 5) // lots of tables means this is most likely a bulletin
			return new ParseTable(sourceDomainName);
		// --- check for list
		Elements cveLists = doc.select("li:contains(CVE), ul:contains(CVE), ol:contains(CVE), dl:contains(CVE)");
		if (cveLists.size() > 0)
			return new ParseList(sourceDomainName);
		// --- check for accordion
		Elements cveAccordions = doc.select("accordion, bolt-accordion, acc, div[class*=accordion], div[id*=accordion]");
		if (cveAccordions.size() > 0)
			return new ParseAccordion(sourceDomainName);
		// --- check for bulletin
		Elements cveBulletins = doc.select("div:contains(Bulletin), div:contains(CVE), span:contains(CVE), p:contains(CVE)");
		if (cveBulletins.size() > 0)
			return new ParseBulletin(sourceDomainName);
		// fall through and use description strategy
		return new ParseCVEDescription(sourceDomainName);
	}

	/**
	 * generic parsing of web page a selected parser strategy
	 * 
	 * @param sSourceURL source url of web page
	 * @param sCVEContentHTML html content of web page
	 */
	@Override
	public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		if (parserStrategy == null)
			parserStrategy = chooseParserStrategy(sCVEContentHTML);
		logger.info("Generic Parsing " + sSourceURL + " with " + parserStrategy.getClass().getSimpleName());
		List<RawVulnerability> genericList = parserStrategy.parseWebPage(sSourceURL, sCVEContentHTML);
		if (!(parserStrategy instanceof ParseCVEDescription)) {
			// throw in whatever ParseCVEDescription can find too
			logger.info("Generic Parsing " + sSourceURL + " with ParseCVEDescription");
			genericList.addAll(new ParseCVEDescription(sSourceURL).parseWebPage(sSourceURL, sCVEContentHTML));
		}
		if (driver != null) driver.quit();
		return genericList;
	}

}
