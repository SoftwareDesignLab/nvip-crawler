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

package fixes.parsers;

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


import edu.rit.se.nvip.db.model.Fix;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

/**
 * Abstract class for FixFinder HTMl Parsers
 *
 * @author Paul Vickers
 * @author Dylan Mulligan
 */
public abstract class FixParser {
    protected final static Logger logger = LogManager.getLogger();
    protected final String cveId;
    protected final String url;

    protected Set<Fix> fixes;
    protected Document DOM;

    protected FixParser(String cveId, String url){
        this.cveId = cveId;
        this.url = url;
    }

    public Set<Fix> parse() {
        // Init list for storing fixes
        this.fixes = new HashSet<>();

        // Attempt to parse page and store returned Document object
        try {
            logger.info("{} is parsing url '{}'...", getClass().getSimpleName(), url);
            this.DOM = Jsoup.parse(new URL(url), 10000);
            // Call abstract method implementation based on instance
            this.parseWebPage();
        }
        catch (IOException e) {
            logger.warn("Failed to parse url '{}': {}", url, e.toString());
        }

        // Log fix finding results
        final int numFixes = this.fixes.size();
        if(numFixes > 0)
            logger.info("{} found {} fixes from url '{}'", getClass().getSimpleName(), numFixes, url);

        // Return collected fixes
        return this.fixes;
    }

    //TODO: Remove this throws unless we really need it, as URL interaction has been
    // moved to parse() and the IOExceptions are handled there
    protected abstract Set<Fix> parseWebPage() throws IOException;

    /**
     * Delegation method to determine which parser should be used to find fixes from the given url.
     *
     * @param cveId CVE ID for which fixes may be found
     * @param url URL to page which will be parsed
     * @return Correct parser to be used
     *
     */
    public static FixParser getParser(String cveId, String url) throws MalformedURLException {
        // Objectify url for domain extraction
        final URL urlObj = new URL(url);
        // Extract domain
        final String domain = urlObj.getHost();

        // Create generic parser that will be used for all unknown urls
        FixParser parser;

        // Choose parser based on domain
        switch (domain) {
            case "nvd.nist.gov":
                parser = new NVDParser(cveId, url);
                break;
            case "cisa.gov":
                parser = new CISAParser(cveId, url);
                break;
            case "access.redhat.com":
                parser = new RedhatParser(cveId, url);
                break;
            case "cxsecurity.com":
                parser = new CXSecurityParser(cveId, url);
                break;
            default:
                parser = new GenericParser(cveId, url);
                break;
        }

        // Return chosen parser instance
        return parser;
    }
}
