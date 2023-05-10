package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.interactions.Actions;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ParseAccordion extends AbstractCveParser implements ParserStrategy {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    /**
     * We need to be able to click accordion dropdowns
     * in case there is hidden data
     * init a headless browser to be able to click around
     * instead of just parsing a static html page
     */
    WebDriver driver = startDynamicWebDriver();

    // init actions to be able to click around
    Actions actions = new Actions(driver);

    String sourceUrl = "";

    /**
     * Generic parser accordion strategy
     * @param sourceDomainName - domain name of source
     */
    public ParseAccordion(String sourceDomainName) {
        this.sourceDomainName = sourceDomainName;
    }

    public void clickAcceptCookies() {
        try {
            WebElement cookiesButton = driver.findElement(By.xpath("//button[text()='Agree' or text()='Accept' or text()='Accept Cookies' or text()='Accept all']"));
            cookiesButton.click();
            logger.info("Accepted Cookies for page " + sourceUrl);
        } catch (NoSuchElementException e) {
            logger.info("No Cookies pop-up found for page " + sourceUrl);
        }
    }

    /**
     * Recursively check element parent to ensure
     * we have accordion root
     * If we find a parent with an "accordion" attribute we know it is not an
     * accordion root
     * @param el - current element we are checking
     * @return - true if accordion root, false otherwise
     */
    public boolean isRootAccordion(Element el) {
        Element par = el.parent();
        if (par == null) return true;
        else if (par.tagName().contains("accordion") || par.id().contains("accordion")) return false;
        else return isRootAccordion(par);
    }

    /**
     * Parse accordion element
     * @param accordion - accordion element to be parsed
     * @return - list of vulnerabilities parsed from accordion children
     */
    private List<CompositeVulnerability> parseAccordion(Element accordion) {
        List<CompositeVulnerability> cves = new ArrayList<>();
        Elements accordionChildren = accordion.children();
        for (Element child : accordionChildren) {
            Set<String> thisAccCVES = getCVEs(child.text());
            if (thisAccCVES.isEmpty()) continue;
            String date = getCVEDate(child.text());
            String description = child.text();
            for (String cve : thisAccCVES) {
                CompositeVulnerability vuln = new CompositeVulnerability(
                        0, sourceUrl, cve, null, date, date, description, sourceDomainName
                );
                cves.add(vuln);
            }
        }
        return cves;
    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        sourceUrl = sSourceURL;
        driver.get(sSourceURL);
        clickAcceptCookies();
        List<CompositeVulnerability> vulnList = new ArrayList<>();


        // search for class name containing "accordion"
        // parse and grab accordion root
        Document doc = Jsoup.parse(driver.getPageSource());
        Elements accordions = doc.select("div[class*=accordion], div[id*=accordion]");
        // make sure we are only looking at root accordions
        accordions.removeIf(el -> !isRootAccordion(el));
        // sometimes data is always visible from html source just hidden
        // some bootstrap pages or pages with buttons might have hidden data until you click on it
        // go through each accordion child and click on it
        for (Element accordion : accordions) {
            vulnList.addAll(parseAccordion(accordion));
        }
        return vulnList;
    }
}
