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
import org.jsoup.select.Elements;

import java.util.List;


/**
 * FixParser implementation that aims to scrape a url from an "unknown" domain
 * via determining, generically, what fix information is on the page. Unlike the other
 * FixParser implementations, this parser does not correlate to a specific domain, and
 * may make use of much more "fuzzy logic" to determine if a page contains fix information
 * and what that information may be. It also may produce incorrect or incomplete fix
 * information as a result of the lack of deterministic methods of collection.
 *
 * @author Paul Vickers
 * @author Dylan Mulligan
 */
public class GenericParser extends FixParser {
    private enum FIX_WORDS {
        FIX,
        MITIGATE,
        MITIGATION,
        RESOLVE,
        RESOLUTION;

        /**
         * Determines if given word is a valid member of this enum.
         *
         * @param word word to test
         * @return whether the word is a valid member of this enum
         */
        public static boolean hasWord(String word) {
            try {
                FIX_WORDS.valueOf(word.toUpperCase());
                return true;
            } catch (Exception ignored) { return false; }
        }
    }

    protected GenericParser(String cveId, String url) {
        super(cveId, url);
    }

    //TODO: Implement logic to determine the location of the desired content (fix information) and collect/store
    // said information with a high confidence of accuracy
    @Override
    protected List<Fix> parseWebPage() {
        final Elements headerObjects = this.DOM.select("h1, h2, h3");
        final List<String> headerTexts = headerObjects.eachText();
        for (String headerText: headerTexts) {
            if(FIX_WORDS.hasWord(headerText)) {
                // Select this section's content
                logger.info("Fix found!");
            }
        }
        return this.fixes;
    }
}
