/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package crawler.htmlparser;

import model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class AndroidParser extends AbstractCveParser {

    /**
     * Parse bulletins listed to source.android.com/docs/security/bulletin/
     * @param domainName - android domain
     */
    public AndroidParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // get publish and modified dates under title
        // this is the first element with em tag
        Element datesEl = doc.select("em").first();
        String publishedDate = "";
        String lastModifiedDate = "";
        StringBuilder description = new StringBuilder();
        if (datesEl != null) {
            // if only published is present, have lastModified also be published
            // sometimes they are separated by just a pipe (|) sometimes they are separated by just "Updated"
            String[] datesSplit;
            String[] updatedSplit = datesEl.text().split("Updated");
            String[] pipeSplit = datesEl.text().split("\\|");
            if (updatedSplit.length > 1) {
                datesSplit = updatedSplit;
                publishedDate = datesSplit[0].split("Published")[1].replace("|", "").trim();
                lastModifiedDate = datesSplit[1].replace("|", "").trim();
            }
            else if (pipeSplit.length > 1) {
                datesSplit = pipeSplit;
                publishedDate = datesSplit[0].split("Published")[1].replace("|", "").trim();
                lastModifiedDate = datesSplit[1].replace("|", "").trim();
            }
            else {
                datesSplit = updatedSplit;
                publishedDate = lastModifiedDate = datesSplit[0].split("Published")[1].trim();
            }

            // get large description under dates
            // go until we do not see a <p> tag
            Element next = datesEl.nextElementSibling();
            while(next != null && next.tagName().equals("p")) {
                description.append(next.text());
                next = next.nextElementSibling();
            }
        }

        // get each table in bulletin
        // filter to just tables that contain CVEs
        Elements tables = doc.select("table:contains(CVE)");
        // foreach table get description above it and parse each CVE id
        for (Element table : tables) {
            // if CVE keyword is found in a table w/ less than 3 columns or w/ no
            // CVE header it is unlikely to have useful CVE information in it
            if (table.children().select("th:contains(CVE)").size() == 0 ||
                    table.children().select("th").size() < 3)
                continue;
            if (table.parent() == null) continue;
            Element prev = table.parent().previousElementSibling();
            String thisDesc = description + (prev == null ? "" : prev.text());
            Elements rows = table.child(1).children();
            // foreach CVE append other useful columns to desc and add to vulnList
            // first get names of columns to map to when appending
            ArrayList<String> categoryNames = new ArrayList<>();
            Elements columnNames = rows.get(0).children();
            Element cveColHeader = columnNames.select(":contains(CVE)").first();
            int cveIndex = columnNames.indexOf(cveColHeader);
            for (Element columnName : columnNames) categoryNames.add(columnName.text());
            // start for loop after the header row
            for (int i = 1 ; i < rows.size() ; i++) {
                Element row = rows.get(i);
                // note: CVE ID is not always the first column in the table
                String cveId = "";
                StringBuilder usefulDesc = new StringBuilder(thisDesc);
                Elements cells = row.children();
                for (int j = 0 ; j < cells.size() ; j++) {
                    Element cell = cells.get(j);
                    String cellText = cell.text();
                    if (j == cveIndex)
                        cveId = getCVEID(cellText);
                    else {
                        String col = ";" + categoryNames.get(j) + ": " + cellText;
                        usefulDesc.append(col);
                    }
                }
                if (cveId.equals("")) continue;
                vulnList.add(new RawVulnerability(
                        sSourceURL, cveId, publishedDate, lastModifiedDate, usefulDesc.toString()
                ));
            }
        }
        return vulnList;
    }
}
