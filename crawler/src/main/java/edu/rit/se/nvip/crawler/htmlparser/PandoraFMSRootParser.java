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

package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class PandoraFMSRootParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "pandorafms";

    public PandoraFMSRootParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse advisories listed to pandorafms.com/en/security/common-vulnerabilities-and-exposures/
     * @param domainName - pandorafms domain
     */
    public PandoraFMSRootParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // get rows in table
        Elements rows = doc.select("tbody").select("tr");
        for(Element row : rows) {
            Elements cells = row.children().select("td");
            if (cells.size() < 3) continue; // skip if not enough columns (shouldn't happen)
            // get CVE from first column
            String cve = cells.get(0).text();
            // get description from 'Vulnerability details' in second column
            String description = cells.get(1).text();
            // get Publication date from third column
            String publishDate = cells.get(2).text();
            // add to vulns list
            vulnList.add(new RawVulnerability(sSourceURL, cve, publishDate, publishDate, description, getClass().getSimpleName()
            ));
        }


        return vulnList;
    }
}
