package fixes;

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

import fixes.parsers.AbstractFixParser;
import fixes.parsers.GenericParser;
import fixes.parsers.NVDParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Runnable thread class for multithreaded FixFinder
 *
 * Used for finding fixes from a provided source
 *
 * @author Dylan Mulligan
 * @author Paul Vickers
 */
public class FixFinderThread implements Runnable {
	private static final Logger logger = LogManager.getLogger(FixFinder.class.getName());
	private final String url;
	private String description;

	// Get the extracted fix description
	public String getDescription(){ return description; }

	public FixFinderThread(String url){
		this.url = url;
	}

	/**
	 * Used for cloning, crawling, and deleting product repos to find patch commits
	 */
	// TODO: this class will mostly be used for delegation. For the url passed in, it will be checked to see which parser
	//  should be used to handle scraping data. I've implemented a basic abstract class and the NVD specific parser as an example.
	@Override
	public void run() {

		AbstractFixParser parser = null;

		// Check to see if we have a parser for the specific domain already (will be way more in the future than just nvd)
		if(url.contains("nvd.nist.gov")){
			parser = new NVDParser(url);

		// If no above domains were recognized, then we use generic parser to try to find a fix?
		}else parser = new GenericParser(url);

		// After determining correct parser, parse the web page for the description and set it
		this.description = parser.parseWebPage();
	}

}
