package fixes.parsers;

import fixes.Fix;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * HTML parser for NVD web pages
 * TODO: put enums in for tags ex. "Patch"
 */
public class NVDParser extends AbstractFixParser{
    public NVDParser(String cveId, String url){
        super(cveId, url);
    }

    // TODO: finish this (paul)
    @Override
    public List<Fix> parseWebPage() {
        List<String> fixSources = new ArrayList<>();

        Document doc;
        try {
            doc = Jsoup.connect(url).get();
            Elements rows = doc.select("div[id=vulnHyperlinksPanel]").first().select("table").first().select("tbody").select("tr");

            for(Element row : rows){
                String url = row.select("a").text();
                Elements spans = row.select("span.badge");
                for(Element span: spans){
                    if(span.text().equalsIgnoreCase("Patch")) fixSources.add(url);
                }
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        System.out.println(fixSources);

        return null;
    }
}
