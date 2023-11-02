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
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.Arrays;
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
//        COUNTERMEASURE;

        /**
         * Determines if given word is a valid member of this enum (case-insensitive).
         *
         * @param word word to test
         * @return whether the word is a valid member of this enum
         */
        public static boolean hasWord(String word) {
            word = word.toUpperCase();
            try {
                FIX_WORDS.valueOf(word);
                return true;
            } catch (Exception ignored) {
                // If no direct match, check if word is plural and try singular form
                final boolean endsWithES = word.endsWith("ES");
                final boolean endsWithS = endsWithES || word.endsWith("S");

                if(endsWithES || endsWithS) {
                    final int endIndex = endsWithES ? 2 : 1;
                    final String trimmedWord = word.substring(0, endIndex);
                    try {
                        FIX_WORDS.valueOf(trimmedWord);
                        return true;
                    } catch (Exception ignored1) { }
                }

                // Return false if no match
                return false;
            }
        }

        private static List<String> stringValues() {
            return Arrays.stream(values()).map(Enum::toString).toList();
        }
    }

    private enum FIX_WORDS_BLACKLIST {
        NO, NOT;

        public static int containsKeywords(String text) {
            text = text.toUpperCase();
            int numKeywords = 0;

            // Get string values for all blacklist keywords
            for (String keyword : FIX_WORDS_BLACKLIST.stringValues()) {
                // Append all fix words (looking for things like "no fix" or "not resolved")
                for (String fixWord : FIX_WORDS.stringValues()) {
                    keyword += " " + fixWord;
                    if(text.contains(keyword)) numKeywords++;
                    // Check past tense/plural forms
//                    else if(!keyword.endsWith("D") && text.contains(keyword + "D")) numKeywords++;
//                    else if(!keyword.endsWith("ED") && text.contains(keyword + "ED")) numKeywords++;
                }
            }

            return numKeywords;
        }

        private static List<String> stringValues() {
            return Arrays.stream(values()).map(Enum::toString).toList();
        }
    }

    protected GenericParser(String cveId, String url) {
        super(cveId, url);
    }

    //TODO: Implement logic to determine the location of the desired content (fix information) and collect/store
    // said information with a high confidence of accuracy
    @Override
    protected List<Fix> parseWebPage() {
        // Select header objects to be potential anchors
        final Elements headerElements = this.DOM.select("h1, h2, h3, h4, h5");


        // Run header words through FIX_WORDS enum, only selecting headers containing a valid member

        // Create container for description elements
        final Elements descriptionElements = new Elements();

        // Iterate over header objects
        for (Element e : headerElements) {
            // Check text and id of header for keywords
            final List<String> words = new ArrayList<>(Arrays.asList(e.text().split(" ")));
            words.add(e.id());
            // Split text on spaces and check each word.
            for (String headerWord : words) {
                // Check if word is a member of FIX_WORDS (case-insensitive)
                if(FIX_WORDS.hasWord(headerWord)) {
                    // Find and store description elements related to the current header
                    descriptionElements.addAll(findDescriptionElements(e));

                    // Filter out elements deemed not part of the fix description
                    filterDescriptionElements(descriptionElements);

                    // Concatenate remaining element texts
                    final String fixDescription = String.join(" ", descriptionElements.eachText());

                    // If data was found, store in a new Fix object and add to list of found fixes
                    if(fixDescription.length() > 0 && isFix(fixDescription))
                        this.fixes.add(new Fix(cveId, fixDescription, url));

                    // Skip to next header
                    break;
                }
            }
        }

        return this.fixes;
    }

    private boolean isFix(String fixDescription) {
        // Get number of words that are blacklisted (blacklist words imply not fixed)
        final int numBlacklistWords = FIX_WORDS_BLACKLIST.containsKeywords(fixDescription);

        // If we find none, is likely a fix, 1 or more would imply is not a fix
        return numBlacklistWords < 1;
    }

    private Elements findDescriptionElements(Element e) {
        final Elements elements = new Elements();
        // Attempt to get next sibling, store if found
        final Element nextSibling = e.nextElementSibling();
        if(nextSibling != null) elements.add(nextSibling);

        // Add all found child objects
        elements.addAll(e.children());

        return elements;
    }

    /**
     * Iterate over selected objects and remove ones not likely to be a part of the fix description
     * NOTE: We expect some descriptions to be stored in one element, but others are equally
     * likely to be split among multiple elements. A good example is hyperlinks, which often
     * divide sections of a body of text into multiple elements, which need to be combined.
     *
     * @param elements elements to filter
     */
    private void filterDescriptionElements(Elements elements) {
        // Init list to store elements that will be removed from the given list
        final List<Element> elementsToRemove = new ArrayList<>();

        // Iterate over elements and add ones marked for removal to the list
        for (Element e : elements) {
            // TODO: Implement filter
            if(false) {
                elementsToRemove.add(e);
            }
        }

        // Remove marked elements
        elements.removeAll(elementsToRemove);
    }
}
