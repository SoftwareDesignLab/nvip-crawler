package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;

import java.util.ArrayList;
import java.util.List;

public class ParseBulletin extends AbstractCveParser implements ParserStrategy {

    public ParseBulletin(String sourceDomainName) {
        this.sourceDomainName = sourceDomainName;
    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        List<CompositeVulnerability> vulnList = new ArrayList<>();



        return vulnList;
    }
}
