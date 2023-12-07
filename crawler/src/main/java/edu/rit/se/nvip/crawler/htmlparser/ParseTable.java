/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.crawler.SeleniumDriver;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.support.ui.ExpectedConditions;

import java.time.Duration;
import java.time.LocalDate;
import java.util.*;

public class ParseTable extends AbstractCveParser implements ParserStrategy {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    SeleniumDriver driver;

    String sourceUrl = "";

    Set<String> allCVEs = new HashSet<>();

    public ParseTable(String sourceDomainName, SeleniumDriver driver) {
        this.sourceDomainName = sourceDomainName;
        this.driver = driver;
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
        
        String xPathContainsCVE = "//tr[td//text()[contains(.,'%s')]]";
        WebElement rowElement = driver.tryFindElement(By.xpath(String.format(xPathContainsCVE, cveList.get(0))));

        String htmlBefore = "";
        WebElement htmlBeforeElement = driver.tryFindElement(By.tagName("tbody"));
        if(htmlBeforeElement != null) htmlBefore = htmlBeforeElement.getAttribute("innerHTML").replace("\n", "").replace("\t", "");

        String htmlAfter = "";
        if(rowElement != null && driver.tryClickElement(rowElement, 5)){
            WebElement htmlAfterElement = driver.tryFindElement(By.tagName("tbody"));
            if(htmlAfterElement != null) htmlAfter = htmlAfterElement.getAttribute("innerHTML").replace("\n", "").replace("\t", "");
        }

        String diff = StringUtils.difference(htmlBefore, htmlAfter).replace("\n", "").replace("\t", "");

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
                            sourceUrl, cve, createdDate, lastModifiedDate, description, getClass().getSimpleName()
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
        if(driver.tryClickElement(By.xpath("//*[contains(@class,'next')]"), 5))
            nextPage = StringUtils.difference(sourceHtml, driver.getDriver().getPageSource());
        else
            logger.warn("Unable to get next page");
        return nextPage;
    }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        sourceUrl = sSourceURL;
        List<RawVulnerability> vulnList = new ArrayList<>();

        // Get page
        String next = driver.tryPageGet(sSourceURL);
        if(next == null) return vulnList;

        driver.clickAcceptCookies();

        // we want to see a brand new page that we also have not seen before
        // so if there is a difference, and the difference contains CVE ids that we have not seen before, keep going
        int count = 0;
        while (!next.equals("")) {
            // try and wait until CVE table is loaded, by waiting for CVE- text
            try {
                // x path table contains text "CVE-"
                By cveBy = By.xpath("//*[text()[contains(.,'CVE-')]]");
                new WebDriverWait(driver.getDriver(), Duration.ofSeconds(5)).until(ExpectedConditions.presenceOfElementLocated(cveBy));
                next = driver.getDriver().getPageSource();
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
        driver.deleteAllCookies();
        return vulnList;
    }
}
