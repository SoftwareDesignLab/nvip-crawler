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
import org.jsoup.select.Elements;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EatonParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "eaton";

    public EatonParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * parse advisories listed to eaton.com/us/en-us/company/news-insights/cybersecurity/security-notifications.html
     * @param domainName - eaton domain
     */
    public EatonParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);
        Elements pdfV = doc.select("pdf-viewer");
        if (pdfV.size() == 0) {
            return vulnList;
        }
        // the given url is a PDF link, download and parse it
        String pdfString = pdfToString(sSourceURL);
        if (pdfString != null && !pdfString.equals("")) {
            pdfString = pdfString.replace("\r", "");

            // get CVE id from String
            Set<String> cves = getCVEs(pdfString);

            String description = "";
            // for description get everything above 4. Remediation & Mitigation
            String[] vulnDetailsSplit = pdfString.split("Remediation & Mitigation");
            if (vulnDetailsSplit.length > 1) {
                description = vulnDetailsSplit[0];
            } else {
            // or just use the entire text
                description = pdfString;
            }

            // publish date get first date under 'Revision Control'
            String publishDate = new Date().toString();
            // last modified date get last date under 'Revision Control'
            String lastModifiedDate = publishDate;

            String[] revisionTableSplit = pdfString.split("Revision Control");
            if (revisionTableSplit.length > 1) {
                Set<String> uniqueDates = new HashSet<>();
                Pattern cvePattern = Pattern.compile(regexDateFormatNumeric);
                Matcher cveMatcher = cvePattern.matcher(revisionTableSplit[1]);
                while (cveMatcher.find())
                    uniqueDates.add(cveMatcher.group());
                publishDate = uniqueDates.stream().findFirst().get();
                lastModifiedDate = uniqueDates.stream().reduce((one, two) -> two).get();
            }
            for (String cve : cves)
                vulnList.add(new RawVulnerability(
                        sSourceURL, cve, publishDate, lastModifiedDate, description, getClass().getSimpleName()
                ));

        }

        return vulnList;
    }
}
