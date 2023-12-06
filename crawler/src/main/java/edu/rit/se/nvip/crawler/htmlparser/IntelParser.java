/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class IntelParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "intel";

    public IntelParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse advisories listed to intel.com/content/www/us/en/security-center/default.html
     * Ex: <a href="https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00714.html">...</a>
     * @param domainName - intel domain
     */
    public IntelParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // get the top table
        Element advTable = doc.select("table").first();
        if (advTable == null) return vulnList;
        // get publish date from table
        Element release = advTable.children().select("td:contains(release)").first();
        if (release == null) return vulnList;
        Element publishEl = release.nextElementSibling();
        if (publishEl == null) return vulnList;
        String publishDate = publishEl.text();
        // get last modified date from table
        Element revised = advTable.children().select("td:contains(revised)").first();
        if (revised == null) return vulnList;
        Element lastModifiedEl = revised.nextElementSibling();
        if (lastModifiedEl == null) return vulnList;
        String lastModifiedDate = lastModifiedEl.text();

        // looks to follow the format:
        // CVEID
        // Description
        // CVSS Base Score
        // CVSS Vector

        // extract foreach CVEID
        Elements cves = doc.select("p:contains(CVEID:)");
        for (Element cve : cves) {
            String line = cve.text();
            String cveID = getCVEID(line);
            if (cveID.equals("")) continue;
            Element next = cve.nextElementSibling();
            // skip the Recommendations sections
            if (next == null || !next.text().contains("Description")) continue;
            String description = next.text();
            description = description.split(": ")[1];
            vulnList.add(new RawVulnerability(
                    sSourceURL, cveID, publishDate, lastModifiedDate, description, getClass().getSimpleName()
            ));
        }

        return vulnList;
    }
}
