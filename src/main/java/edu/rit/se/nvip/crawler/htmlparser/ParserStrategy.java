package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;

import java.util.List;

public interface ParserStrategy {

    List<CompositeVulnerability> parseWebPageGeneric(String sSourceURL, String sCVEContentHTML);
}
