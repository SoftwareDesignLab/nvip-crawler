/ **
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
* /

package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class DotCMSParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "dotcms";

    public DotCMSParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse advisories listed to dotcms.com/docs/latest/known-security-issues
     * @param domainName - dotCMS domain
     */
    public DotCMSParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // get CVES from references part of page
        Element referencesHeader = doc.select("th:contains(References)").first();
        if (referencesHeader == null) return vulnList;
        Element referencesTD = referencesHeader.nextElementSibling();
        if (referencesTD == null) return vulnList;
        Set<String> cves = getCVEs(referencesTD.text());
        // if no cves, return empty list
        if (cves.size() == 0) return vulnList;

        // get date from date row of table
        String date = "";
        Element dateHeader = doc.select("th:contains(Date:)").first();
        if (dateHeader != null) {
            Element dateTD = dateHeader.nextElementSibling();
            if (dateTD != null) {
                date = dateTD.text();
            }
        }

        // get description from description row of table
        String description = "";
        Element descriptionHeader = doc.select("th:contains(Description:)").first();
        if (descriptionHeader != null) {
            Element descriptionTD = descriptionHeader.nextElementSibling();
            if (descriptionTD != null) {
                description = descriptionTD.text();
            }
        }

        for (String cve : cves)
            vulnList.add(new RawVulnerability(
                    sSourceURL, cve, date, date, description, getClass().getSimpleName()
            ));

        return vulnList;
    }
}
