package crawler.htmlparser;

import model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class AristaParser extends AbstractCveParser {

    public AristaParser(String domainName) {sourceDomainName = domainName;}

    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // get last modified date and publish date from table at top of page
        // sometimes dates are either chronological or reverse chronological
        // can keep track using revision number
        float revision = 0.0f;
        String lastModifiedDate = "";
        String publishedDate = "";
        Element tbody = doc.select("tbody").first();
        if (tbody == null) return vulnList;
        Elements rows = tbody.children().select("tr");
        for (Element row : rows) {
            // skip the header row
            if (row.text().contains("Revision")) continue;
            // get the initial release row
            else if (row.text().toLowerCase().contains("initial release")) {
                revision = 1.0f;
                String date = getCVEDate(row.text());
                if (lastModifiedDate.equals("")) lastModifiedDate = date;
                publishedDate = date;
                continue;
            }
            Elements cols = row.children();
            float thisRevision = Float.parseFloat(cols.get(0).text());
            String dateInRow = getCVEDate(row.text());
            if (!dateInRow.equals("")) {
                if (publishedDate.equals("")) {
                    publishedDate = lastModifiedDate = dateInRow;
                } else if (thisRevision > revision) {
                    lastModifiedDate = dateInRow;
                }
            }
        }
        if (lastModifiedDate.equals("")) lastModifiedDate = publishedDate;
        if (publishedDate.equals("")) return vulnList;

        // get description under Description h2 tag
        Element descriptionEl = doc.select("h2:contains(Description),h3:contains(Description)").first();
        StringBuilder description = new StringBuilder();
        if (descriptionEl == null) return vulnList;
        Element nextEl = descriptionEl.nextElementSibling();
        while (nextEl != null && nextEl.tagName().equals("p")) {
            description.append(nextEl.text());
            nextEl = nextEl.nextElementSibling();
        }

        // get CVEs on page, usually towards top of page
        Set<String> cves = getCVEs(doc.text());
        for (String cve : cves)
            vulnList.add(new RawVulnerability(
                    0, sSourceURL, cve, null, publishedDate, lastModifiedDate, description.toString(), sourceDomainName
            ));


        return vulnList;
    }
}
