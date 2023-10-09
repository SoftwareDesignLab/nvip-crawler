package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.crawler.SeleniumDriver;

import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class ParseAccordion extends AbstractCveParser implements ParserStrategy {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    SeleniumDriver driver;

    String sourceUrl = "";

    /**
     * Generic parser accordion strategy
     * @param sourceDomainName - domain name of source
     */
    public ParseAccordion(String sourceDomainName, SeleniumDriver driver) {
        this.driver = driver;
        this.sourceDomainName = sourceDomainName;
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

    private List<RawVulnerability> parseCVEsFromAccordion(String accordionText) {
        List<RawVulnerability> cves = new ArrayList<>();
        Set<String> thisAccCVES = getCVEs(accordionText);
        if (thisAccCVES.isEmpty()) return cves;
        GenericDate date = extractDate(accordionText);
        String rawDate = date.getRawDate();
        if (rawDate == null || rawDate.equals("")) rawDate = LocalDate.now().toString();
        GenericDate genericLastMod = extractLastModifiedDate(accordionText);
        String lastMod = genericLastMod.getRawDate();
        if (lastMod == null || lastMod.equals("")) lastMod = rawDate;
        for (String cve : thisAccCVES) {
            RawVulnerability vuln = new RawVulnerability(
                    sourceUrl, cve, rawDate, lastMod, accordionText, getClass().getSimpleName());
            cves.add(vuln);
        }
        return cves;
    }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        sourceUrl = sSourceURL;
        List<RawVulnerability> vulnList = new ArrayList<>();

        String originalHtml = driver.tryPageGet(sSourceURL);
        if(originalHtml == null) return vulnList;

        driver.clickAcceptCookies();

        // search for class name containing "accordion"
        // parse and grab accordion root
        Document doc = Jsoup.parse(originalHtml);
        Elements accordions = doc.select("accordion, bolt-accordion, acc, div[class*=accordion], div[id*=accordion]");
        // make sure we are only looking at root accordions
        accordions.removeIf(el -> !isRootAccordion(el));
        // sometimes data is always visible from html source just hidden
        // some bootstrap pages or pages with buttons might have hidden data until you click on it
        // go through each accordion child and click on it
        for (Element accordion : accordions) {
            Elements accordionChildren = accordion.children();
            while (accordionChildren.size() == 1) {
                accordion = accordionChildren.first();
                accordionChildren = accordion.children();
            }
            for (Element child : accordionChildren) {
                StringBuilder childText = new StringBuilder(child.text());
                String diff = "";

                // try and click on child to see if we can gain any more CVE info from it
                WebElement childWebElement = driver.tryFindElement(By.xpath(jsoupToXpath(child)));
                if(childWebElement != null && driver.tryClickElement(childWebElement, 1)) {
                    String newHtml = driver.getDriver().getPageSource();
                    diff = StringUtils.difference(originalHtml, newHtml);
                }

                if (!diff.equals(""))
                    childText.append(diff, 0, 200);
                vulnList.addAll(parseCVEsFromAccordion(childText.toString()));
            }
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
                    vulnList.addAll(parseCVEsFromAccordion(accText.toString()));
                }
            }
        }
        driver.deleteAllCookies();
        return vulnList;
    }
}
