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
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class ParseBulletin extends AbstractCveParser implements ParserStrategy {

    public ParseBulletin(String sourceDomainName) {
        this.sourceDomainName = sourceDomainName;
    }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        // bounds to grab relevant description text for bulletins
        final int SUBSTRING_BOUNDS = 300;

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);
        String docText = doc.text();
        // grab CVE IDs from page
        Set<String> cveIDs = getCVEs(docText);
        // for each cve ID, find it in text, and get text around it
        for (String cve : cveIDs) {
            // find cve in text
            int cveIndex = docText.indexOf(cve);
            // if not found, skip
            if (cveIndex == -1) continue;
            // grab text around it
            String cveText = docText.substring(Math.max(cveIndex - SUBSTRING_BOUNDS, 0), Math.min(cveIndex + SUBSTRING_BOUNDS, docText.length()));
            GenericDate cveDate = extractDate(cveText);
            GenericDate lastModifiedDate = extractLastModifiedDate(cveText);
            if (cveDate.getRawDate() == null) {
                cveDate = extractDate(docText);
                if (cveDate.getRawDate() == null) {
                    cveDate = new GenericDate(LocalDate.now().toString());
                }
            }
            if (lastModifiedDate.getRawDate() == null) {
                lastModifiedDate = extractLastModifiedDate(docText);
                if (lastModifiedDate.getRawDate() == null)
                    lastModifiedDate = cveDate;
            }

            // create new composite vulnerability
            RawVulnerability vuln = new RawVulnerability(
                    sSourceURL, cve, cveDate.getRawDate(), lastModifiedDate.getRawDate(), cveText, getClass().getSimpleName()
            );
            // add to list
            vulnList.add(vuln);
        }

        return vulnList;
    }
}
