package fixes.parsers;

import fixes.Fix;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CISAParser extends AbstractFixParser{

    public CISAParser(String cveId, String url){
        super(cveId, url);
    }

    @Override
    public List<Fix> parseWebPage() throws IOException {
        List<Fix> fixes = new ArrayList<>();

        Document doc = Jsoup.connect(url).get();

        Elements headers = doc.select("div[id=1-full__main]").first().select("h");

        return fixes;
    }


}
