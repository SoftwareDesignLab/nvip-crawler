package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.By;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ParseTable extends AbstractCveParser implements ParserStrategy {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    /**
     * We need special clicking and updating functionality for tables
     * init a headless browser to be able to click around
     * instead of just parsing a static html page
     */
    WebDriver driver = startDynamicWebDriver();

    // init actions to be able to click around
    Actions actions = new Actions(driver);

    String sourceUrl = "";

    Set<String> allCVEs = new HashSet<>();

    public ParseTable(String sourceDomainName) {
        this.sourceDomainName = sourceDomainName;
    }

    /**
     * Parse row of table into useful vulnerability information
     * click on row and get new information if possible
     * @param row - Jsoup row element to be parsed
     * @return - CompositeVulnerability object with information from row
     */
    private List<CompositeVulnerability> rowToVuln(Element row) {
        List<CompositeVulnerability> rowVulns = new ArrayList<>();

        String rowText = row.text();
        Set<String> cveIDs = getCVEs(rowText);
        ArrayList<String> cveList = new ArrayList<>(cveIDs);
        allCVEs.addAll(cveList);
        if (cveIDs.isEmpty()) return rowVulns;

        // click on row and see if we can grab any more html

        // click on any cookie agree button before clicking on row
        try {
            WebElement cookiesButton = driver.findElement(By.xpath("//button[text()='Agree']"));
            cookiesButton.click();
            logger.info("cookies clicked");
        } catch (NoSuchElementException e) {
            logger.warn("No cookies button found");
        }

        WebElement rowElement = driver.findElement(By.xpath(String.format("//tr[ .//*[text()='%s']]", cveList.get(0))));
        String r = rowElement.getAttribute("innerHTML");

        String htmlBefore = driver.findElement(By.tagName("tbody")).getAttribute("innerHTML");
        rowElement.click();
        String htmlAfter = driver.findElement(By.tagName("tbody")).getAttribute("innerHTML");
        String diff = StringUtils.difference(htmlBefore, htmlAfter);
        String description = "";
        // if we gain new information from clicking, add it onto our html to parse
        if (!diff.equals("")) {
            StringBuilder newHtml = new StringBuilder();
            // first cut off diff where the rest is contained in the before text
            while (!htmlBefore.contains(diff)) {
//                logger.info("cutting off diff..." + diff.substring(0, 10));
                newHtml.append(diff, 0, 10);
                diff = diff.substring(10);
            }
            Element newHtmlElements = Jsoup.parse(newHtml.toString());
            description = newHtmlElements.text();
        }
        else {
//            logger.info("no new information gained from clicking");
            description = rowText;
        }


        // TODO: change this date logic with a more generalized format selection and usage
        //      currently this most likely is not enough for all cases of dates in tables
        //      NVIP-crawler#9
        String date = "";
        Pattern longDatePattern = Pattern.compile(regexDates);
        Pattern yyyyMMddPattern = Pattern.compile("([12]\\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01]))");
        Matcher longMatch = longDatePattern.matcher(rowText);
        Matcher shortMatch = yyyyMMddPattern.matcher(rowText);
        if (longMatch.find())
            date = longMatch.group();
        else if (shortMatch.find())
            date = shortMatch.group();
        else
            logger.warn("No date found for {}" + cveIDs);

        for (String cve : cveList)
            rowVulns.add(
                    new CompositeVulnerability(
                            0, sourceUrl, cve, null, date, date, description, sourceDomainName
                    )
            );

        return rowVulns;
    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        sourceUrl = sSourceURL;
        List <CompositeVulnerability> vulnList = new ArrayList<>();

        // get the page
        driver.get(sSourceURL);
        String sourceHtml = driver.getPageSource();

        Document doc = Jsoup.parse(sourceHtml);
        // get the main table by looking for table header that contains CVE
        Element tableHeader = doc.select("thead:contains(CVE)").first();
        if (tableHeader == null) return vulnList;
        Element tableRows = tableHeader.nextElementSibling();
        if (tableRows == null) return vulnList;
        for (Element row : tableRows.children()) {
            List<CompositeVulnerability> rowVulns = rowToVuln(row);
            vulnList.addAll(rowVulns);
        }


        // assumes the button class contains next text
        try {
            WebElement nextButton = driver.findElement(By.xpath("//*[contains(@class,'next')]"));
            nextButton.click();
            logger.info("next button clicked");
            String diff = StringUtils.difference(sourceHtml, driver.getPageSource());
            // we want to see a brand new page that we also have not seen before
            // so if there is a difference, and the difference contains CVE ids that we have not seen before, keep going
            while (!diff.equals("")) {
                Set<String> thisPageCVEs = getCVEs(diff);
                if (!Collections.disjoint(thisPageCVEs, allCVEs)) break;
                logger.info("new page source found");

                doc = Jsoup.parse(diff);
                // get the main table by looking for table header that contains CVE
                tableHeader = doc.select("thead:contains(CVE)").first();
                if (tableHeader == null) return vulnList;
                tableRows = tableHeader.nextElementSibling();
                if (tableRows == null) return vulnList;
                for (Element row : tableRows.children()) {
                    List<CompositeVulnerability> rowVulns = rowToVuln(row);
                    vulnList.addAll(rowVulns);
                }

                nextButton = driver.findElement(By.xpath("//*[contains(@class,'next')]"));
                nextButton.click();
                diff = StringUtils.difference(sourceHtml, driver.getPageSource());
            }
        } catch (NoSuchElementException e) {
            logger.info("No next button found");
            return vulnList;
        }

        return vulnList;
    }
}
