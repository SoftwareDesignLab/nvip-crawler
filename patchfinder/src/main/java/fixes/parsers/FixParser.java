package fixes.parsers;

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

import fixes.Fix;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

/**
 * Abstract class for FixFinder HTMl Parsers
 *
 * @author Paul Vickers
 */
public abstract class FixParser {
    protected final String cveId;
    protected final String url;

    protected FixParser(String cveId, String url){
        this.cveId = cveId;
        this.url = url;
    }

    // Returns a list of fixes found from web page.
    public abstract List<Fix> parseWebPage() throws IOException;

    /**
     * Delegation method to determine which parser should be used to find fixes from the given url.
     *
     * @param cveId CVE ID for which fixes may be found
     * @param url URL to page which will be parsed
     * @return Correct parser to be used
     *
     * TODO: make this return more than just nvd/cisa etc, will come as we make more parsers
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
            default:
                parser = new GenericParser(cveId, url);
                break;
        }

        // Return chosen parser instance
        return parser;
    }
}
