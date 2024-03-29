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

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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

public class TrendMicroParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "zerodayinitiative";

    public TrendMicroParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse advisories listed to TrendMicro.com/vinfo/us/threat-encyclopedia/vulnerability
     * Specifically 'Security Update Overview' pages from Zero Day Initiative
     * @param domainName - zero day initiative domain (zerodayinitative.com/.....)
     */
    public TrendMicroParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // get date - blog posts refer to these overviews as Patch Tuesday
        // so expect this date to always be the second Tuesday of a given month
        Element dateEl = doc.select("h1.title").first();
        if (dateEl == null) return vulnList;
        dateEl = dateEl.nextElementSibling();
        if (dateEl == null) return vulnList;
        String date = dateEl.text().split("\\|")[0].trim();

        // get the big table element containing all the CVEs
        Elements tableEls = doc.select("table");
        Element table = tableEls.first();
        if (table == null) return null;
        Element tableBody = table.children().select("tbody").first();
        if (tableBody == null) return null;
        Elements rows = tableBody.children();
        for (Element row : rows) {
            String text = row.text();
            if (text.contains("CVE-")) {
                // get each block inside the row
                Elements rowTDs = row.children().select("td");
                // cve box
                Element cveTD = rowTDs.first();
                if (cveTD == null) continue;
                String cveId = cveTD.text();
                // "Title" box we will use for description
                Element descTD = cveTD.nextElementSibling();
                if (descTD == null) continue;
                String description = descTD.text();
                vulnList.add(new RawVulnerability(sSourceURL, cveId, date, date, description, getClass().getSimpleName()
                ));
            }
        }
        return vulnList;
    }
}
