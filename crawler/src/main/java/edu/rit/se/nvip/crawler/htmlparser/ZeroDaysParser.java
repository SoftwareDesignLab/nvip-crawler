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

public class ZeroDaysParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "cybersecurityworks";

    public ZeroDaysParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse advisories listed to cybersecurityworks.com/zerodays-vulnerability-list/
     * @param domainName - zero days domain
     */
    public ZeroDaysParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        Element rightColumn = doc.select("div.second-half").first();
        if (rightColumn == null) return vulnList;

        // get CVE ID from right column
        Element cveEl = rightColumn.children().select("li:contains(CVE Number)").first();
        if (cveEl == null) return vulnList;
        Element cveIdEl = cveEl.children().select("span").first();
        if (cveIdEl == null) return vulnList;
        String cve = cveIdEl.text();

        // get publish date from top row
        String publishDate = "";
        Element dateHeader = doc.select("h4:contains(Date)").first();
        if (dateHeader != null) {
            Element dateEl = dateHeader.nextElementSibling();
            if (dateEl != null)
                publishDate = dateEl.text();
        }

        // get description in p tags under Description header
        Element descHeader = doc.select("h3:contains(Description)").first();
        StringBuilder description = new StringBuilder();
        if (descHeader != null) {
            Element nextDesc = descHeader.nextElementSibling();
            while (nextDesc != null) {
                description.append(nextDesc.text());
                nextDesc = nextDesc.nextElementSibling();
            }
        }

        // get last modified date from last date in timeline on the bottom
        String lastModifiedDate = publishDate;
        Element timeline = doc.select("div#timeline").last();
        if (timeline != null) {
            Element lastDate = timeline.children().select("li").last();
            if (lastDate != null)
                lastModifiedDate = lastDate.children().select("strong").text().replace(":", "");
        }

        vulnList.add(new RawVulnerability(sSourceURL, cve, publishDate, lastModifiedDate, description.toString(), getClass().getSimpleName()
        ));

        return vulnList;
    }
}
