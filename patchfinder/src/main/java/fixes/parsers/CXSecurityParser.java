package fixes.parsers;


import edu.rit.se.nvip.db.model.Fix;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
public class CXSecurityParser extends FixParser {
    protected CXSecurityParser(String cveId, String url) {
        super(cveId, url);
    }

    @Override
    protected Set<Fix> parseWebPage() throws IOException {
        Set<String> fixSources = new HashSet<>();

        // Retrieve description
        String description = String.valueOf(this.DOM.select("h6").first().text());

        Elements references  = this.DOM.select("table").last().select("td").select("div");
        for(Element row : references){
            String url = row.text();
            fixSources.add(url);

        }

       // For each URL, find the correct parser for it and add the fixes found for that URL
        for(String fixSource : fixSources){
            FixParser parser = FixParser.getParser(cveId, fixSource);
            this.fixes.addAll(parser.parse());
        }
        return this.fixes;
    }

}
