package fixes.urlfinders;

import fixes.FixFinder;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class CXSecurityUrlFinder  extends FixUrlFinder{
    public CXSecurityUrlFinder() { }

    @Override
    public ArrayList<String> getUrls(String cveId) throws IOException {

        logger.info("Getting fixes for CVE: {}", cveId);

        // Get all sources for the cve
        ArrayList<String> urlList = FixFinder.getDatabaseHelper().getSpecificCveSources(cveId);

        // Test NVD direct cve page
        final String directSource = "https://cxsecurity.com/cveshow/" + cveId;
        if(testConnection(directSource)) {
            urlList.addAll(this.scrapeReferences(directSource));
        }

        return urlList;
    }

    private List<String> scrapeReferences(String url) throws IOException {
        // Isolate the HTML for the references table
        Elements rows =  this.getDOM(url).select("table").last().select("td").select("div");

        // For each URL stored in the table, if it has a "Patch" badge associated with it, add it to fixSources
        List<String> fixSources = new ArrayList<>();
        for(Element row : rows){
            String refUrl = row.text();
            fixSources.add(url);
        }

        return fixSources;
    }


}
