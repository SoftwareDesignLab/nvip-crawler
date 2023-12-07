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

package fixes.parsers;


import edu.rit.se.nvip.db.model.Fix;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
public class CXSecurityParser extends FixParser {
    protected CXSecurityParser(String cveId, String url) {
        super(cveId, url);
    }

    @Override
    protected Set<Fix> parseWebPage() throws IOException {
        Set<String> fixSources = new HashSet<>();

        // Retrieve description
        String description = String.valueOf(this.DOM.select("h6").first().text());

        Elements references  = this.DOM.select("table").last().select("td").select("div");
        for(Element row : references){
            String url = row.text();
            fixSources.add(url);

        }

       // For each URL, find the correct parser for it and add the fixes found for that URL
        for(String fixSource : fixSources){
            FixParser parser = FixParser.getParser(cveId, fixSource);
            this.fixes.addAll(parser.parse());
        }
        return this.fixes;
    }

}
