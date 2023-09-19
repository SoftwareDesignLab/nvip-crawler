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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;
import fixes.FixFinderThread;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import java.net.URL;


/**
 * HTML parser for RedHat web pages
 *
 * @author Dylan Mulligan
 * @author Gregory Lynskey
 */
public class RedhatParser extends FixParser {

    protected RedhatParser(String cveId, String url) {
        super(cveId, url);
    }

    // TODO: Will return two fixes, one for solutions and one for security, duplicates are a possibility
    @Override
    protected List<Fix> parseWebPage() throws IOException {
        List<Fix> fixes = new ArrayList<>();

        if (url.contains("/solutions/")){

            fixes.add(getResolutionFix(new URL(url)));
            URL securityLink = buildSecurityLink();
//            fixes.add(getMitigationFix(securityLink));

        } else if (url.contains("/security/")) {

//            fixes.add(getMitigationFix(new URL(url)));
//            URL solutionsLink = findSolutionLink();
//            fixes.add(getResolutionFix(solutionsLink));

        }

        return fixes;
    }

    /**
     * Parses the redhat.com/solutions/ page to get the resolution information
     * @param urlObj redhat.com/solution/ URL object
     * @return fix containing the new information
     */
    private Fix getResolutionFix(URL urlObj) throws IOException {

        Document doc = Jsoup.parse(urlObj, 10000);
        String resolution = doc.select("section[class=field_kcs_resolution_txt]").select("p").text();
        return new Fix(cveId, resolution, urlObj.toString());
    }

    /**
     * Parses the redhat.com/security/ page to get the mitigation information
     * @param urlObj redhat.com/security/ URL object
     * @return fix containing the new information
     */
    private Fix getMitigationFix(URL urlObj) throws IOException{
        Document doc = Jsoup.parse(urlObj, 10000);
        return null;
    }

    /**
     * Given the cveID builds a link to the redhat.com/security page
     * @return url to the security page
     */
    private URL buildSecurityLink() throws MalformedURLException {
        String securityLink = "https://access.redhat.com/security/cve/" + cveId;
        return new URL(securityLink);
    }

    /**
     * Searches the redhat.com/security page for a link to the /solution page
     * @return url to solution page
     */
    private URL findSolutionLink(){
        return null;
    }
}
