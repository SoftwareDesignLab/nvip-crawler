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
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ABBParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "abb.com";

    public ABBParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse root advisories page listed to global.abb/group/en/technology/cyber-security/alerts-and-notifications
     * Individual pages links to pdf files, download and parse those
     * @param domainName - global abb domain
     */
    public ABBParser(String domainName) {
        sourceDomainName = domainName;
    }

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
            // get CVE id from String
            Set<String> cves = getCVEs(pdfString);

            // date sometimes differs in location but there is always 1 date in the form yyyy-mm-dd
            String date = "";
            Pattern cvePattern = Pattern.compile(regexDateYearMonthDay);
            Matcher cveMatcher = cvePattern.matcher(pdfString);
            if (cveMatcher.find())
                date = cveMatcher.group();

            // get description from Summary section
            String description = "";
            pdfString = pdfString.replace("\r", "");
            String[] summarySplit = pdfString.split("Summary \n");
            // get the entire string as description by default - some old ones don't have a different formats
            if (summarySplit.length > 1) {
                String summary = summarySplit[1];
                String[] endSplit = summary.split("© Copyright");
                description = endSplit[0];
            } else
                description = pdfString;

            // usually just 1 but we will loop over the set just to be sure
            for (String cve : cves)
                vulnList.add(new RawVulnerability(sSourceURL, cve,  date, date, description, getClass().getSimpleName()));
        }
        return vulnList;
    }
}
