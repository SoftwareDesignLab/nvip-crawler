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

    /**
     * Extract date helper - get substring bounds
     * @return array of substring bounds
     */
    private int[] getSubstringBounds(String text, String keyword) {
        // bounds to isolate date text for individual CVE ID's in bulletin
        final int DATE_BOUNDS = 40;

        int[] bounds = new int[2];
        int keywordIndex = text.toLowerCase().indexOf(keyword);
        if (keywordIndex == -1) return bounds;
        bounds[0] = keywordIndex;
        bounds[1] = Math.min(keywordIndex + DATE_BOUNDS, text.length());
        return bounds;
    }

    // search for date keywords, grab dates around it
    private GenericDate extractDate(String text) {
        // search for "Published" "Created" "Modified" "Updated" keywords, grab dates around it
        // check a subtext for a date based on these keywords
        if (text.toLowerCase().contains("published")) {
            // grab date around published
            int[] bounds = getSubstringBounds(text, "published");
            return new GenericDate(text.substring(bounds[0], bounds[1]));
        } else if (text.toLowerCase().contains("created")) {
            // grab date around created
            int[] bounds = getSubstringBounds(text, "created");
            return new GenericDate(text.substring(bounds[0], bounds[1]));
        }
        // otherwise try to find any sort of date in the text (this might give back rogue dates in descriptions, etc...)
        return new GenericDate(text);
    }

    private GenericDate extractLastModifiedDate(String text) {
        // search for "Published" "Created" "Modified" "Updated" keywords, grab dates around it
        // check a subtext for a date based on these keywords
        if (text.toLowerCase().contains("modified")) {
            // grab date around modified
            int[] bounds = getSubstringBounds(text, "modified");
            return new GenericDate(text.substring(bounds[0], bounds[1]));
        } else if (text.toLowerCase().contains("updated")) {
            // grab date around updated
            int[] bounds = getSubstringBounds(text, "updated");
            return new GenericDate(text.substring(bounds[0], bounds[1]));
        }
        // otherwise try to find any sort of date in the text (this might give back rogue dates in descriptions, etc...)
        return new GenericDate(text);
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
