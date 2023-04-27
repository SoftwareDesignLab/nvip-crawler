package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.interactions.Actions;

import java.util.List;

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

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        // get the page
        driver.get(sSourceURL);

        // init actions to be able to click around
        Actions actions = new Actions(driver);

        //TODO: functionality to click on a <tr> to get more details

        //TODO: functionality to click on next page until done

        return null;
    }
}
