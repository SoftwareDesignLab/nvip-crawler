package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ParseList extends AbstractCveParser implements ParserStrategy {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    // Needs to be tested on a website with a list and CVE IDs
    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        List<CompositeVulnerability> vulnList = new ArrayList<>();

        // Grab all of the li elements from the page
        Document doc = Jsoup.parse(sCVEContentHTML);
        Elements lists = doc.select("li:contains(CVE)");

        for (Element list : lists) {
            String list_text = list.text();

            String cve = getCVEID(list_text);

            String date = getCVEDate(list_text);

            // Check if there is something that has details/description
            Element desc_el = list.select(":contains(detail), :contains(description)").first();
            String desc = null;

            if(desc_el != null){
                desc = desc_el.text();
            }
            else{
                // Check the first <p> if its CVE related
                desc_el = list.select("p:matchesOwn(" + regexAllCVERelatedContent + ")").first();

                if(desc_el != null){
                    desc = desc_el.text();
                }
                else{
                    // If there is no <p> that has CVE stuff, check the inner text of the <li>
                    String test = list.ownText();
                    Pattern cvePattern = Pattern.compile(regexAllCVERelatedContent);
                    Matcher cveMatcher = cvePattern.matcher(test);
                    if (cveMatcher.find())
                        desc = cveMatcher.group();
                }
            }

            CompositeVulnerability vuln = new CompositeVulnerability(0, sSourceURL, cve, null, date, null, desc, sourceDomainName);
            logger.info(vuln);
        }

        return vulnList;
    }
}
