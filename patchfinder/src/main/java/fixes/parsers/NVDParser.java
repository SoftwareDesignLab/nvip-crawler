package fixes.parsers;

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

import fixes.Fix;
import fixes.FixFinderThread;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * HTML parser for NVD web pages
 *
 * @author Paul Vickers
 */
public class NVDParser extends FixParser {
    public static final String PATCH = "Patch";

    public NVDParser(String cveId, String url){
        super(cveId, url);
    }

    /**
     * Method used to parse an NVD CVE vulnerability webpage for fixes. Main functionality is to
     * scrape for the references table and then delegate to other parsers for those sources.
     *
     * @return List of fixes for the CVE
     * @throws IOException if an error occurs during scraping
     */
    @Override
    public List<Fix> parseWebPage() throws IOException{
        List<Fix> fixes = new ArrayList<>();

        // Connect to NVD page using Jsoup
        Document doc = Jsoup.connect(url).get();

        // Isolate the HTML for the references table
        Elements rows = doc.select("div[id=vulnHyperlinksPanel]").first().select("table").first().select("tbody").select("tr");

        // For each URL stored in the table, if it has a "Patch" badge associated with it, add it to fixSources
        List<String> fixSources = new ArrayList<>();
        for(Element row : rows){
            String url = row.select("a").text();
            Elements spans = row.select("span.badge");
            for(Element span: spans){
                if(span.text().equalsIgnoreCase(PATCH)) fixSources.add(url);
            }
        }

        // For each URL with the "Patch" tag, find the correct parser for it and add the fixes found for that URL
        for(String fixSource : fixSources){
            FixParser parser = FixFinderThread.findCorrectParser(cveId, fixSource);
            fixes.addAll(parser.parseWebPage());
        }

        return fixes;
    }
}
