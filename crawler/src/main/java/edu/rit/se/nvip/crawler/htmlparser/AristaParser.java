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
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

// TODO: Add doctring to this
public class AristaParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "arista";

    public AristaParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    public AristaParser(String domainName) {sourceDomainName = domainName;}

    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // get last modified date and publish date from table at top of page
        // sometimes dates are either chronological or reverse chronological
        // can keep track using revision number
        float revision = 0.0f;
        String lastModifiedDate = "";
        String publishedDate = "";
        Element tbody = doc.select("tbody").first();
        if (tbody == null) return vulnList;
        Elements rows = tbody.children().select("tr");
        for (Element row : rows) {
            // skip the header row
            if (row.text().contains("Revision")) continue;
            // get the initial release row
            else if (row.text().toLowerCase().contains("initial release")) {
                revision = 1.0f;
                String date = getCVEDate(row.text());
                if (lastModifiedDate.equals("")) lastModifiedDate = date;
                publishedDate = date;
                continue;
            }
            Elements cols = row.children();
            float thisRevision = Float.parseFloat(cols.get(0).text());
            String dateInRow = getCVEDate(row.text());
            if (!dateInRow.equals("")) {
                if (publishedDate.equals("")) {
                    publishedDate = lastModifiedDate = dateInRow;
                } else if (thisRevision > revision) {
                    lastModifiedDate = dateInRow;
                }
            }
        }
        if (lastModifiedDate.equals("")) lastModifiedDate = publishedDate;
        if (publishedDate.equals("")) return vulnList;

        // get description under Description h2 tag
        Element descriptionEl = doc.select("h2:contains(Description),h3:contains(Description)").first();
        StringBuilder description = new StringBuilder();
        if (descriptionEl == null) return vulnList;
        Element nextEl = descriptionEl.nextElementSibling();
        while (nextEl != null && nextEl.tagName().equals("p")) {
            description.append(nextEl.text());
            nextEl = nextEl.nextElementSibling();
        }

        // get CVEs on page, usually towards top of page
        Set<String> cves = getCVEs(doc.text());
        for (String cve : cves)
            vulnList.add(new RawVulnerability(
                    sSourceURL, cve, publishedDate, lastModifiedDate, description.toString(), getClass().getSimpleName()
            ));


        return vulnList;
    }
}
