package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;

import java.util.List;

public interface ParserStrategy {

    List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML);
}
