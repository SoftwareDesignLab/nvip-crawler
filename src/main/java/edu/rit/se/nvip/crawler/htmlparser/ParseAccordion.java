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
        else if (par.className().contains("accordion") || par.id().contains("accordion")) return false;
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
//            String date = getCVEDate(child.text());
            GenericDate date = new GenericDate(child.text());
            String rawDate = date.getRawDate();
            String description = child.text();
            for (String cve : thisAccCVES) {
                CompositeVulnerability vuln = new CompositeVulnerability(
                        0, sourceUrl, cve, null, rawDate, rawDate, description, sourceDomainName
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
        Elements accordions = doc.select("accordion, bolt-accordion, acc, div[class*=accordion], div[id*=accordion]");
        // make sure we are only looking at root accordions
        accordions.removeIf(el -> !isRootAccordion(el));
        // sometimes data is always visible from html source just hidden
        // some bootstrap pages or pages with buttons might have hidden data until you click on it
        // go through each accordion child and click on it
        for (Element accordion : accordions) {
            vulnList.addAll(parseAccordion(accordion));
        }
        // or sometimes there is a decent amount of header and body elements next to each other
        // Ex: ASUS
        Elements headers = doc.select("h1, h2, h3, h4, h5, h6, div[id*=header], div[class*=header]");
        Elements bodies = doc.select("p, div[id*=body], div[class*=body]");
        // we can consider pages that carry at least 20 of each, then we can assume this
        // is either a large accordion or list style page we can parse
        if (headers.size() > 20 && bodies.size() > 20) {
            for (Element header : headers) {
                // get next element, if it is contained in bodies, we can assume the two point to the same vuln
                Element next = header.nextElementSibling();
                if (next == null) continue;
                else if (bodies.contains(next)) {
                    StringBuilder accText = new StringBuilder();
                    accText.append(header.text());
                    while (next != null && !headers.contains(next)) {
                        accText.append(" ");
                        accText.append(next.text());
                        next = next.nextElementSibling();
                    }

                    //TODO: duplicated code fragment with up above
                    Set<String> thisAccCVES = getCVEs(accText.toString());
                    if (thisAccCVES.isEmpty()) continue;
                    GenericDate date = new GenericDate(accText.toString());
                    String rawDate = date.getRawDate();
                    String description = accText.toString();
                    for (String cve : thisAccCVES) {
                        CompositeVulnerability vuln = new CompositeVulnerability(
                                0, sourceUrl, cve, null, rawDate, rawDate, description, sourceDomainName
                        );
                        vulnList.add(vuln);
                    }

                }
            }
        }
        return vulnList;
    }
}
