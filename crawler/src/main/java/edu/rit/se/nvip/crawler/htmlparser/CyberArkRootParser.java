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

public class CyberArkRootParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "cyberark";

    public CyberArkRootParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse bulletin table in ampere product security page
     * @param rootDomain - labs.cyberark.com/cyberark-labs-security-advisories/
     */
    public CyberArkRootParser(String rootDomain) { sourceDomainName = rootDomain; }

    /**
     * Takes in tr element, locates td associated with given string and grabs what
     * is inside that cell
     * @return - text inside cell
     */
    private String getCellValue(Element row, int colIndex) {
        // each cell contains a span that references the column it is in
        Element cell = row.children().get(colIndex);
        if (cell == null) return "";
        return cell.text();
//        String cellText = cell.text();
//        String[] valueSplit = cellText.split(colIdentifier);
//        // 1 or less in split means there is no value inside this table cell
//        if (valueSplit.length > 1)
//            return valueSplit[1].trim();
//        return "";
    }

    /**
     * parse root CyberArk vuln web page table
     * @param sSourceURL - labs.cyberark.com/cyberark-labs-security-advisories/
     * @param sCVEContentHTML - parsed html of source url
     * @return - CVE list from bulletin table
     */
    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // table columns are the following:
        // Year, ID, CVE, Vendor, Product, CWE, Researcher, Read More, Date

        // get table rows
        Element table = doc.select("table#tableOne").first();
        if (table == null) return vulnList;
        Element tableBody = table.children().select("tbody").first();
        if (tableBody == null) return vulnList;
        Elements rows = tableBody.children();
        int i = 0;
        for (Element row : rows) {
            i++;
            // get CVE ID from row
            String cveId = getCellValue(row, 2);

            // if the cve id is invalid, don't use
            if (getCVEs(cveId).isEmpty()) {
                continue;
            }

            // get date from row
            String date = getCellValue(row, 8);
            // have our description be a combination of
            // Vendor, Product, and CWE columns
            String vendor = getCellValue(row, 3);
            String product = getCellValue(row, 4);
            String cwe = getCellValue(row, 5);
            String description = vendor + " " + product + " " + cwe;

            vulnList.add(new RawVulnerability(
                    sSourceURL, cveId, date, date, description, getClass().getSimpleName()
            ));
        }

        return vulnList;
    }

}
