package fixes.parsers;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;

/**
 * HTML parser for NVD web pages
 */
public class NVDParser extends AbstractFixParser{
    public NVDParser(String url){
        super(url);
    }

    // TODO: finish this (paul)
    @Override
    public String parseWebPage() {
        String fixDescription = "";

        Document doc;
        try {
            doc = Jsoup.connect(url).get();
            Element table = doc.select("div[id=vulnHyperlinksPanel]").first().select("table[class=table table-striped table-condensed table-bordered detail-table]").first();
            Elements urls = table.select("a");

            for(Element e : urls){
                System.out.println("Possible url: " + e.text());
            }

        } catch (IOException e) {
            doc = null;
            throw new RuntimeException(e);
        }


        return fixDescription;
    }
}
