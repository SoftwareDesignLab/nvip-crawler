package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;

import java.util.List;

public class ParseTable implements ParserStrategy {

    @Override
    public List<CompositeVulnerability> parseWebPageGeneric(String sSourceURL, String sCVEContentHTML) {
        return null;
    }
}
