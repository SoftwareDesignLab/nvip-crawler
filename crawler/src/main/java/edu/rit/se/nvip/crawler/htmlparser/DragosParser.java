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

import java.util.ArrayList;
import java.util.List;

public class DragosParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "dragos";

    public DragosParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse advisories listed to dragos.com/advisories
     * @param domainName dragos domain
     */
    public DragosParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        Element cveColumn = doc.select("p.sa-title-sm:contains(CVE)").first();
        if (cveColumn == null) return vulnList;
        // get all elements after CVE ID in column
        // if empty or says N/A return empty list
        Element nextInColumn = cveColumn.nextElementSibling();
        if (nextInColumn == null || nextInColumn.text().contains("N/A")) return vulnList;
        ArrayList<String> cves = new ArrayList<>();
        while (nextInColumn != null) {
            cves.add(nextInColumn.text().trim());
            nextInColumn = nextInColumn.nextElementSibling();
        }

        // no desc on these pages, have the desc be the page title
        String title = "";
        Element titleEl = doc.select("h1.advisory_intro__title").first();
        if (titleEl != null)
            title = titleEl.text();

        String date = "";
        Element dateEl = doc.select(":matchesOwn([0-9]+[-/][0-9]+[-/][0-9]+)").first();
        if (dateEl != null)
            date = dateEl.text();

        for (String cve : cves)
            vulnList.add(new RawVulnerability(
                    sSourceURL, cve, date, date, title, getClass().getSimpleName()
            ));

        return vulnList;
    }
}
