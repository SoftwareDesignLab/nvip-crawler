package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.RawVulnerability;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.openqa.selenium.*;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.interactions.MoveTargetOutOfBoundsException;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;
import java.time.LocalDate;
import java.util.*;

public class ParseTable extends AbstractCveParser implements ParserStrategy {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    WebDriver driver;

    WebDriverWait wait;

    // init actions to be able to click around
    Actions actions;

    String sourceUrl = "";

    Set<String> allCVEs = new HashSet<>();

    public ParseTable(String sourceDomainName, WebDriver driver) {
        this.sourceDomainName = sourceDomainName;
        this.driver = driver;
        wait = new WebDriverWait(driver, Duration.ofSeconds(5));
        actions = new Actions(driver);
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
    private boolean retryClick(WebElement element) {
        boolean result = false;
        int attempts = 0;
        while(attempts < 2) {
            try {
                actions.scrollToElement(element).perform();
                actions.click(element).perform();
                result = true;
                break;
            } catch(StaleElementReferenceException e) {
            }
            attempts++;
        }
        return result;
    }



    /**
     * Parse row of table into useful vulnerability information
     * click on row and get new information if possible
     * @param row - Jsoup row element to be parsed
     * @return - RawVulnerability object with information from row
     */
    private List<RawVulnerability> rowToVuln(Element row) {
        List<RawVulnerability> rowVulns = new ArrayList<>();

        String rowText = row.text();
        Set<String> cveIDs = getCVEs(rowText);
        ArrayList<String> cveList = new ArrayList<>(cveIDs);
        allCVEs.addAll(cveList);
        if (cveIDs.isEmpty()) return rowVulns;

        // click on row and see if we can grab any more html
        String diff = "";
        String htmlBefore = "";
        WebElement rowElement;
        try {
            String xPathContainsCVE = "//tr[td//text()[contains(.,'%s')]]";
            rowElement = driver.findElement(By.xpath(String.format(xPathContainsCVE, cveList.get(0))));
            // logger.info("Found row for " + cveIDs);
            // try and click element and every child of element
            htmlBefore = driver.findElement(By.tagName("tbody")).getAttribute("innerHTML").replace("\n", "").replace("\t", "");
            try {
                new WebDriverWait(driver, Duration.ofSeconds(5)).until(ExpectedConditions.elementToBeClickable(rowElement));
                actions.scrollToElement(rowElement).perform();
                actions.click(rowElement).perform();
            } catch (StaleElementReferenceException | MoveTargetOutOfBoundsException e) {
                if (!retryClick(rowElement)) logger.info("Unable to click row for " + cveIDs);
            }
            String htmlAfter = driver.findElement(By.tagName("tbody")).getAttribute("innerHTML").replace("\n", "").replace("\t", "");
            diff = StringUtils.difference(htmlBefore, htmlAfter).replace("\n", "").replace("\t", "");
        } catch (StaleElementReferenceException | MoveTargetOutOfBoundsException e) {
            // logger.info("Row not found for " + cveIDs);
        }
        String description = "";
        // if we gain new information from clicking, add it onto our html to parse
        if (!diff.equals("")) {
            StringBuilder newHtml = new StringBuilder();
            // first cut off diff where the rest is contained in the before text
            while (!htmlBefore.contains(diff) && diff.length() > 10) {
                newHtml.append(diff, 0, 10);
                diff = diff.substring(10);
            }
            Element newHtmlElements = Jsoup.parse(newHtml.toString());
            description = newHtmlElements.text();
        }
        else description = rowText;
        String createdDate = LocalDate.now().toString();
        GenericDate genericDate = extractDate(rowText);
        String lastModifiedDate;
        GenericDate genericLastMod = extractLastModifiedDate(rowText);
        if (genericDate.getRawDate() != null)
            createdDate = genericDate.getRawDate();
        if (genericLastMod.getRawDate() != null)
            lastModifiedDate = genericLastMod.getRawDate();
        else
            lastModifiedDate = createdDate;

        for (String cve : cveList)
            rowVulns.add(
                    new RawVulnerability(
                            sourceUrl, cve, createdDate, lastModifiedDate, description
                    )
            );
        return rowVulns;
    }

    private List<RawVulnerability> parseTableSource(String sourceHtml) {
        List <RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sourceHtml);
        // get the main table by looking for table header that contains CVE
        Element tableHeader = doc.select("thead:contains(CVE)").first();
        Element tableBody = doc.select("tbody:contains(CVE)").first();
        if (tableHeader == null && tableBody == null) return vulnList;
        if (tableHeader != null) {
            Element tableRows = tableHeader.nextElementSibling();
            if (tableRows == null) return vulnList;
            for (Element row : tableRows.children()) {
                List<RawVulnerability> rowVulns = rowToVuln(row);
                vulnList.addAll(rowVulns);
            }
        } else {
            for (Element row : tableBody.children()) {
                List<RawVulnerability> rowVulns = rowToVuln(row);
                vulnList.addAll(rowVulns);
            }
        }
        return vulnList;
    }

    private String getNextPage(String sourceHtml) {
        String nextPage = "";
        try {
            By nextButtonBy = By.xpath("//*[contains(@class,'next')]");
            WebElement nextButton = wait.until(ExpectedConditions.elementToBeClickable(nextButtonBy));
            actions.scrollToElement(nextButton).perform();
            actions.click(nextButton).perform();
            logger.info("Next button clicked for Table at " + sourceUrl);
            nextPage = StringUtils.difference(sourceHtml, driver.getPageSource());
        } catch (NoSuchElementException | TimeoutException e) {
            // logger.info("No Next button found for Table at " + sourceUrl);
        } catch (ElementNotInteractableException ei) {
            logger.warn("Next Button found raises ElementNotInteractableException...");
        } catch (StaleElementReferenceException s) {
            logger.warn("Next Button found raises StaleElementReferenceException...");
        }
        return nextPage;
    }

    private void tryPageGet(String sSourceURL) {
        int tries = 0;
        while (tries < 2) {
            try {
                driver.get(sSourceURL);
                break;
            } catch (TimeoutException e) {
                logger.info("Retrying page get...");
                tries++;
            }
        }
    }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        sourceUrl = sSourceURL;
        // get the page
        tryPageGet(sSourceURL);
        if (driver.getPageSource() == null) return new ArrayList<>();
//        driver.get(sSourceURL);
        // click on any cookie agree button before trying to parse and click on anything else
        clickAcceptCookies();
        List<RawVulnerability> vulnList = new ArrayList<>();

        // assumes the button class contains next text
        String next = driver.getPageSource();
        // we want to see a brand new page that we also have not seen before
        // so if there is a difference, and the difference contains CVE ids that we have not seen before, keep going
        int count = 0;
        while (!next.equals("")) {
            // try and wait until CVE table is loaded, by waiting for CVE- text
            try {
                // x path table contains text "CVE-"
                By cveBy = By.xpath("//*[text()[contains(.,'CVE-')]]");
                new WebDriverWait(driver, Duration.ofSeconds(5)).until(ExpectedConditions.presenceOfElementLocated(cveBy));
                next = driver.getPageSource();
            } catch (TimeoutException e) {
                logger.warn("Timeout waiting for CVE- text to be present");
            }
            Set<String> thisPageCVEs = getCVEs(next);
//            logger.info(driver.getPageSource());
            logger.info("Page " + count++ + " has " + thisPageCVEs.size() + " CVEs");
            if (thisPageCVEs.isEmpty()) break;
            if (!Collections.disjoint(thisPageCVEs, allCVEs)) break;
            logger.info("Parsing new page of CVEs at " + sourceUrl);
            vulnList.addAll(parseTableSource(next));
            next = getNextPage(next);
        }

        return vulnList;
    }
}
