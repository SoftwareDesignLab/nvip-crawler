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
package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class TrustWaveParser extends AbstractCveParser {

    /**
     * Parse advisories listed to trustwave.com/en-us/resources/blogs/spiderlabs-blog/
     * @param domainName - trustwave domain
     */
    public TrustWaveParser(String domainName) { sourceDomainName = domainName; }

    /**
     * remove any (, ), or : from CVE title string
     * @param cveId - unformatted title string
     * @return - formatted title string, without (,),:
     */
    private String extractCVEId(String cveId) {
        // simple character removals, can probably replace this with a fancy regex at some point
        cveId = cveId.replace("(", "");
        cveId = cveId.replace(")", "");
        cveId = cveId.replace(":", "");
        return cveId;
    }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // get page date at top below title
        String date = "";
        Element dateEl = doc.select("div.blog-post-date").first();
        if (dateEl != null) {
            Element datePubEl = dateEl.children().select("span").first();
            if (datePubEl != null)
                date = datePubEl.text();
        }

        // get h3's containing CVE-, if none, chances are this page has 1 or 0 CVEs
        Elements cveHeaders = doc.select("h3:contains(CVE-)");
        // for each header found, extract CVE ID, and loop through description below it
        List<String> foundCVEs = new ArrayList<>();
        for (Element cveHeader : cveHeaders) {
            String[] lineSplit = cveHeader.text().split(" ");
            // we can assume this String will init based on the query match from above
            String cveId = "";
            for (String s : lineSplit) {
                if (s.contains("CVE")) {
                    // get rid of any parantheses or colon
                    cveId = extractCVEId(s);
                    // and add to found CVEs to be queried against later
                    foundCVEs.add(cveId);
                }
            }
            Element next = cveHeader.nextElementSibling();
            StringBuilder description = new StringBuilder();
            while(next != null && !next.tagName().contains("h")) {
                description.append(next.text());
                next = next.nextElementSibling();
            }
            vulnList.add(new RawVulnerability(sSourceURL, cveId, date, date, description.toString(), getClass().getSimpleName()
            ));
        }
        // check to see if CVE in title, if any CVE id found does not match current vulnList, add it
        // with desc being Summary or overview
        Element title = doc.select("h1.blog-post-title").first();
        if (title == null) return vulnList;
        String[] titleSplit = title.text().split(" ");
        List<String> titleCVEs = new ArrayList<>();
        // get each String in titleSplit that matches "CVE-"
        for (String s : titleSplit) {
            if (s.contains("CVE-")) {
                titleCVEs.add(extractCVEId(s));
            }
        }
        // for each string if it matches a cveId already parsed, remove it
        List<String> titleCVEcopy = new ArrayList<>(titleCVEs);
        for (String thisCve : titleCVEcopy) {
            if (foundCVEs.contains(thisCve))
                titleCVEs.remove(thisCve);
        }
        // for each remaining CVE...
        if (titleCVEs.size() > 0) {
            String description = "";
            // get summary
            Elements summaryEl = doc.select("h3:contains(Summary)");
            if (summaryEl.size() > 0) {
                Element summaryPara = summaryEl.first().nextElementSibling();
                if (summaryPara != null)
                    description = summaryPara.text();
            }
            // if !summary, get overview
            else {
                Element overview = doc.select("h3:contains(Overview)").first();
                Element overviewPara = overview.nextElementSibling();
                if (overviewPara != null)
                    description = overviewPara.text();
            }
            // add it to vuln list
            for (String remainingCVE : titleCVEs) {
                vulnList.add(new RawVulnerability(sSourceURL, remainingCVE, date, date, description, getClass().getSimpleName()
                ));
            }
        }
        
        return vulnList;
    }
}
