package fixes.parsers;

import fixes.Fix;
import fixes.FixFinderThread;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * HTML parser for NVD web pages
 *
 * @author Paul Vickers
 */
public class NVDParser extends AbstractFixParser{
    public static final String PATCH = "Patch";

    public NVDParser(String cveId, String url){
        super(cveId, url);
    }

    /**
     * Method used to parse an NVD CVE vulnerability webpage for fixes. Main functionality is to
     * scrape for the references table and then delegate to other parsers for those sources.
     *
     * @return List of fixes for the CVE
     * @throws IOException if an error occurs during scraping
     */
    @Override
    public List<Fix> parseWebPage() throws IOException{
        List<Fix> fixes = new ArrayList<>();

        // Connect to NVD page using Jsoup
        Document doc = Jsoup.connect(url).get();

        // Isolate the HTML for the references table
        Elements rows = doc.select("div[id=vulnHyperlinksPanel]").first().select("table").first().select("tbody").select("tr");

        // For each URL stored in the table, if it has a "Patch" badge associated with it, add it to fixSources
        List<String> fixSources = new ArrayList<>();
        for(Element row : rows){
            String url = row.select("a").text();
            Elements spans = row.select("span.badge");
            for(Element span: spans){
                if(span.text().equalsIgnoreCase(PATCH)) fixSources.add(url);
            }
        }

        // For each URL with the "Patch" tag, find the correct parser for it and add the fixes found for that URL
        for(String fixSource : fixSources){
            AbstractFixParser parser = FixFinderThread.findCorrectParser(cveId, fixSource);
            fixes.addAll(parser.parseWebPage());
        }
        System.out.println(fixSources);

        return fixes;
    }
}
