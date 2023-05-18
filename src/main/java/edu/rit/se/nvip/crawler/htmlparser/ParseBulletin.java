package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
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
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        // bounds to grab relevant description text for bulletins
        final int SUBSTRING_BOUNDS = 300;

        List<CompositeVulnerability> vulnList = new ArrayList<>();
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
            String cveText = docText.substring(cveIndex - SUBSTRING_BOUNDS, cveIndex + SUBSTRING_BOUNDS);
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
            CompositeVulnerability vuln = new CompositeVulnerability(
                    0, sSourceURL, cve, null, cveDate.getRawDate(), lastModifiedDate.getRawDate(), cveText, sourceDomainName
            );
            // add to list
            vulnList.add(vuln);
        }



        return vulnList;
    }
}
