package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.interactions.Actions;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class ParseTable extends AbstractCveParser implements ParserStrategy {

    /**
     * We need special clicking and updating functionality for tables
     * init a headless browser to be able to click around
     * instead of just parsing a static html page
     */
    WebDriver driver = startDynamicWebDriver();

    public ParseTable(String sourceDomainName) {
        this.sourceDomainName = sourceDomainName;
    }

    /**
     * Parse row of table into useful vulnerability information
     * click on row and get new information if possible
     * @param row - Jsoup row element to be parsed
     * @return - CompositeVulnerability object with information from row
     */
    private CompositeVulnerability rowToVuln(Element row) {
        //TODO: functionality to click on a <tr> to get more details
        String rowText = row.text();
        Set<String> cveIDs = getCVEs(rowText);
        String date = getDate(rowText);

        return new CompositeVulnerability();
    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        List <CompositeVulnerability> vulnList = new ArrayList<>();

        // get the page
        driver.get(sSourceURL);

        // init actions to be able to click around
        Actions actions = new Actions(driver);

        String diff = StringUtils.difference("table", "tableeeeeeee");

        Document doc = Jsoup.parse(driver.getPageSource());
        // get the main table by looking for table header that contains CVE
        Element tableHeader = doc.select("thead:contains(CVE)").first();
        if (tableHeader == null) return vulnList;
        Element tableRows = tableHeader.nextElementSibling();
        if (tableRows == null) return vulnList;
        for (Element row : tableRows.children()) {
            CompositeVulnerability rowVuln = rowToVuln(row);
            vulnList.add(rowVuln);
        }




        //TODO: functionality to click on next page until done

        return null;
    }
}
