package fixes.parsers;

import fixes.Fix;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
public class cxsecurityParser extends FixParser {
    protected cxsecurityParser(String cveId, String url) {
        super(cveId, url);
    }

    @Override
    protected List<Fix> parseWebPage() throws IOException {
        List<String> fixSources = new ArrayList<>();

        // Retrieve description
        String description = String.valueOf(this.DOM.select("h6").first().text());

        //retrieve references
        Document doc = Jsoup.connect(url).get();

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
