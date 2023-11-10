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
