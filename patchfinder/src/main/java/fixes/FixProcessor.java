package fixes;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.io.IOException;
import java.net.URL;

public abstract class FixProcessor {
    // Logger instance for FixProcessors
    protected static final Logger logger = LogManager.getLogger();

    // Utility method for getting DOM from string URL, throws IOException in case of an error
    protected Document getDOM(String url) throws IOException {
        return Jsoup.parse(new URL(url), 10000);
    }
}
