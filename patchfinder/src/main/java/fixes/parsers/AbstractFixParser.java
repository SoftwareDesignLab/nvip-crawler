package fixes.parsers;

import fixes.Fix;

import java.util.List;

/**
 * Abstract class for FixFinder HTMl Parsers
 */
public abstract class AbstractFixParser {
    protected final String cveId;
    protected final String url;

    public AbstractFixParser(String cveId, String url){
        this.cveId = cveId;
        this.url = url;
    }

    // Returns a list of fixes found from web page.
    public abstract List<Fix> parseWebPage();
}
