package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.RawVulnerability;
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
