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
import edu.rit.se.nvip.model.CompositeVulnerability;

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
	private ParserStrategy parserStrategy = new ParseCVEDescription();
	
	public GenericCveParser(String domainName) {
		sourceDomainName = domainName;
	}

	public GenericCveParser(String domainName, ParserStrategy parserStrategy) {
		sourceDomainName = domainName;
		this.parserStrategy = parserStrategy;
	}

	/**
	 * generic parsing of web page a selected parser strategy
	 * 
	 * @param sSourceURL source url of web page
	 * @param sCVEContentHTML html content of web page
	 */
	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		logger.info("Generic Parsing " + sSourceURL + " with " + parserStrategy.getClass().getSimpleName());
		return parserStrategy.parseWebPage(sSourceURL, sCVEContentHTML);
	}



}
