package fixes.parsers;

import fixes.Fix;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
public class CXSecurityParser extends FixParser {
    protected CXSecurityParser(String cveId, String url) {
        super(cveId, url);
    }

    @Override
    protected List<Fix> parseWebPage() {
        List<String> fixSources = new ArrayList<>();

        // Retrieve description
        String description = String.valueOf(this.DOM.select("h6").first().text());

        Elements references  = this.DOM.select("table").last().select("td").select("div");
        for(Element row : references){
            String url = row.text();
            fixSources.add(url);

        }

        // TODO: Remove when class is migrated to type UrlParser
       // For each URL, find the correct parser for it and add the fixes found for that URL
        for(String fixSource : fixSources){
            FixParser parser = FixParser.getParser(cveId, fixSource);
            this.fixes.addAll(parser.parse());
        }
        return this.fixes;
    }

}
