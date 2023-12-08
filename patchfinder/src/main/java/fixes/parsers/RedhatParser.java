/**
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
*/

package fixes.parsers;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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


import edu.rit.se.nvip.db.model.Fix;
import org.jsoup.Jsoup;

import java.io.IOException;
import java.util.HashSet;
import java.net.URL;
import java.util.Set;

/**
 * HTML parser for redhat web pages
 */
public class RedhatParser extends FixParser {
    protected RedhatParser(String cveId, String url){
        super(cveId, url);
    }

    protected Set<Fix> parseWebPage() throws IOException{
        throw new UnsupportedOperationException();
    }

    /**
     * Delegates and parses the specified webpage using the RedHat Sub classes
     * @return list of all found fixes
     */
    @Override
    public Set<Fix> parse(){
        // Init fixes list
        this.fixes = new HashSet<>();

        // Delegate to correct sub-parser
        // Parser : URL
        // RedhatSolutionsParser : <url>
        // RedhatBugzillaParser : <url>
        // RedhatSecurityParser : <url>
        final RedhatParser parser;
        if (url.contains("/solutions/") || url.contains("bugzilla.")) {
            if (url.contains("/solutions/")){
                parser = new RedhatSolutionsParser(cveId, url);
            } else {
                parser = new RedhatBugzillaParser(cveId, url);
            }
            try {
                parser.DOM = Jsoup.parse(new URL(url), 10000);
                this.fixes.addAll(parser.parseWebPage());
            } catch (IOException e) {
                logger.warn("Failed to parse url '{}': {}", url, e.toString());
            }
        }
//        } else if (url.contains("/security/")) {
//            //TODO: Find way to get the DOM for security page
//        }

        return this.fixes;
    }
}
