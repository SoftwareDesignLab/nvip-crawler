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
import edu.rit.se.nvip.utils.UtilHelper;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.time.LocalDate;

@Slf4j
public class ParseCVEDescription extends AbstractCveParser implements ParserStrategy  {

    /**
     * Generic parser list strategy
     * @param sourceDomainName - domain name of source
     */
    public ParseCVEDescription(String sourceDomainName) {
        this.sourceDomainName = sourceDomainName;
    }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        List<RawVulnerability> vulnerabilities = new ArrayList<>();

        Document document = Jsoup.parse(sCVEContentHTML);
        Elements myHTMLElements = document.select(":matchesOwn(" + regexAllCVERelatedContent + ")");
        String sCVEContent = myHTMLElements.text();

        Map<String, Integer> cveIDsInPage = getUniqueCVEIDs(sCVEContent, false);

        /*
         * Case 1: if no CVE ID regex exists in the page then ignore this source
         */
        if (cveIDsInPage.size() == 0) {
            log.debug("No CVE related content was found at URL: " + sSourceURL);
            return vulnerabilities;
        }

        if (containsChineseChars(sCVEContent)) {
            log.debug("Foreign chars were found at URL: " + sSourceURL);
            return vulnerabilities;
        }

        log.debug("Page URL: " + sSourceURL + "\t Found " + cveIDsInPage.size() + " CVE(s): " + cveIDsInPage);
        // pickURL(sSourceURL); // add this url to our list, to update our crawl source
        // URLs at the end.

        /*
          Case 2: There is a single CVE ID on the page. The whole content is
          potentially related to this CVE ID
         */
        if (cveIDsInPage.size() == 1) {
            /*
              the whole page content includes a single CVE ID. Extract platform/version and
              description, save and return.
             */

            String cveId = (String) getUniqueCVEIDs(sCVEContent, false).keySet().toArray()[0];
            String version = getPlatformVersion(sCVEContent);

            // save vulnerability
            String dateTimeNow = LocalDate.now().toString();
            RawVulnerability vuln = new RawVulnerability(sSourceURL, cveId, dateTimeNow, dateTimeNow, sCVEContent, getClass().getSimpleName());
            vulnerabilities.add(vuln);
            return vulnerabilities;
        }

        /*
          Case 3: There are multiple CVE-IDs on this page. Now split the page into tags
          (sentences?) and pick vulnerability attributes from individual tag texts. You
          may need to split a tag element further if it includes multiple CVE IDs! EX:
          https://www.exploit-db.com/exploits/42518
         */

        Map<String, RawVulnerability> vulnMap = new HashMap<>();

        /*
          Do some pre-processing on the page elements
         */
        preProcessPageElements(myHTMLElements);

        List<String> allSentences = myHTMLElements.eachText();
        for (int indexSentence = 0; indexSentence < allSentences.size(); indexSentence++) {
            String currentSentence = allSentences.get(indexSentence);
            Map<String, Integer> cveIDMapInSentence = getUniqueCVEIDs(currentSentence, true);
            Object[] cveIDsInSentence = cveIDMapInSentence.keySet().toArray();
            /*
              Case 3.1: There are no CVE IDs on this tag text skip it, because we are
              trying to find sentences with a CVE ID first.
             */
            if (cveIDsInSentence.length == 0)
                continue;

            /*
              Case 3.2: Multiple CVE IDs on the tag, check if you need to split the tag text
              further???
             */
            boolean aBlockOfCveIdsInTheSentence = false;
            if (cveIDsInSentence.length > 1) {

                Object[] cveIDDistances = cveIDMapInSentence.values().toArray();
                log.debug("CVE ID distances: " + Arrays.deepToString(cveIDDistances));
                aBlockOfCveIdsInTheSentence = checkCveIdDistances(cveIDDistances);

                if (!aBlockOfCveIdsInTheSentence) {

                    /*
                      Case 3.2.1: There are multiple CVEs in the tag, and they are apart from each
                      other. Split the tag into multiple sentences. Conditions: (1) Make sure that
                      the sentence is long enough to contain valuable info for each CVE ID.
                      (2):Split the tag if it is worth it to split (not a link etc.)
                     */
                    boolean bTheSentenceHasValuableInfo = sentenceContainsValuableInfoForCVE(currentSentence, cveIDsInSentence.length);
                    Element tag = myHTMLElements.get(indexSentence);
                    boolean bWorthsToSplit = (tag == null) ? bTheSentenceHasValuableInfo : !tag.tagName().startsWith("li") && !tag.tagName().startsWith("h") && !tag.tagName().startsWith("a");
                    log.debug("&&&Splitting sentence:  #ofCVE: " + cveIDsInSentence.length + ", Sent. Length: " + currentSentence.length() + ", Tag Name: " + tag + ", TheSentenceHasValuableInfo: " + bTheSentenceHasValuableInfo
                            + ", bWorthsToSplit: " + bWorthsToSplit + ", Sentence: " + currentSentence.replace("\n", ""));

                    if (bTheSentenceHasValuableInfo && bWorthsToSplit) {

                        List<String> childSentences = tokenizeTagTextAccordingToCVEIDRegex(currentSentence);

                        allSentences.remove(indexSentence);
                        for (int i = childSentences.size() - 1; i >= 0; i--) {
                            String childSentence = childSentences.get(i);
                            allSentences.add(indexSentence, childSentence);

                            // Added a sentence, so add a corresponding element object to the element list
                            myHTMLElements.add(indexSentence, null);
                        }

                        // Advance indexSentence till we find a sentence with a CVE ID
                        currentSentence = allSentences.get(indexSentence);
                        while (getFirstCveIdFromString(currentSentence) == null) {
                            indexSentence++;
                            currentSentence = allSentences.get(indexSentence);
                        }
                    }
                }
            }

            // If we are here, then this sentence must have at least one CVE ID
            String cveIDOfCurrentSentence = getFirstCveIdFromString(currentSentence);
            if (cveIDOfCurrentSentence == null) {
                log.error("Oops! There must be something wrong! Check this page! Sentence Index: " + indexSentence + ", CurrentSentence: " + currentSentence + "\n All Sentences: " + allSentences);
            }

            // if there is a prior sentence start looking for vulnerability attributes from there
            int startIndex = findStartIndex(myHTMLElements, indexSentence);

            /*
              extract version info. Start from the suggested startIndex and search
              sentences till you hit a new CVE ID. First look at the current sentence!
             */

            String version = getPlatformVersion(allSentences.get(indexSentence));
            int index = startIndex;
            while (version == null) {
                if (index == allSentences.size() || (index - startIndex > 5)) // nothing to look more!
                    break;
                String sentenceToLook = allSentences.get(index);
                String nextCVEID = getFirstCveIdFromString(sentenceToLook);
                if (nextCVEID == null || nextCVEID.equalsIgnoreCase(cveIDOfCurrentSentence)) {
                    version = getPlatformVersion(sentenceToLook);
                } else
                    break; // either you found it or hit to the next CVE ID!

                index++;
            }

            /*
              extract description. Search sentences till you hit another CVE ID
             */
            StringBuilder sbDescription = new StringBuilder();
            for (int i = startIndex; i < allSentences.size(); i++) {
                String aSentence = allSentences.get(i);
                String nextCVEID = getFirstCveIdFromString(aSentence);
                if (nextCVEID == null || nextCVEID.equalsIgnoreCase(cveIDOfCurrentSentence)) {
                    sbDescription.append("\n");
                    sbDescription.append(aSentence);
                } else
                    break;
            }

            // add vulnerability
            String dateTimeNow = LocalDate.now().toString();
            if (aBlockOfCveIdsInTheSentence)
                for (Object o : cveIDsInSentence) {
                    if (sentenceContainsValuableInfoForCVE(sbDescription.toString(), cveIDsInSentence.length)) {
                        RawVulnerability vuln;
                        if(!vulnMap.containsKey((String)o)){
                            vuln = new RawVulnerability(sSourceURL, (String) o, dateTimeNow, dateTimeNow, sbDescription.toString(), getClass().getSimpleName());
                        }
                        else{
                            vuln = vulnMap.get((String)o);
                            vuln.setDescription(vuln.getDescription() + sbDescription.toString());
                        }
                        vulnMap.put(vuln.getCveId(), vuln);
                    }
                }
            else {
                if (sentenceContainsValuableInfoForCVE(sbDescription.toString(), 1)) {
                    RawVulnerability vuln;
                    if(!vulnMap.containsKey(cveIDOfCurrentSentence)){
                        vuln = new RawVulnerability(sSourceURL, cveIDOfCurrentSentence, dateTimeNow, dateTimeNow, sbDescription.toString(), getClass().getSimpleName());
                    }
                    else{
                        vuln = vulnMap.get(cveIDOfCurrentSentence);
                        vuln.setDescription(vuln.getDescription() + sbDescription.toString());
                    }
                    vulnMap.put(vuln.getCveId(), vuln);
                } else {
                    log.debug("Ignoring this CVE! ID: " + cveIDOfCurrentSentence + ", Description: " + sbDescription);
                }
            }
        }

        log.debug(vulnMap.size() + " of " + cveIDsInPage.size() + " CVEs were scraped from URL:" + sSourceURL + " - " + (cveIDsInPage.size() - vulnMap.size()) + " were ignored!");
        return new ArrayList<>(vulnMap.values());
    }

    /**
     * Merge very short tags
     * @param myHTMLElements - elements matching CVE-related text
     */
    private void preProcessPageElements(Elements myHTMLElements) {
        Pattern pattern = Pattern.compile(regexCVEID);
        int index = 0;
        while (index < myHTMLElements.size()) {
            String elementText = myHTMLElements.get(index).text();
            if (pattern.matcher(elementText).matches() && (elementText.length() <= 2 * regexCVEID.length())) {
                // merge this element with previous one
                if (index - 1 >= 0) {
                    myHTMLElements.get(index - 1).appendText(" " + elementText);
                    myHTMLElements.remove(index);
                    continue; // do not increment
                }
            }
            index++;
        }
    }

    /**
     * if you have a repeating CVE IDs, then consider them as a single one
     * check if we can merge them
     * @param cveIDDistances how similar are the IDs
     * @return - true if we can merge them, false otherwise
     */
    private boolean checkCveIdDistances(Object[] cveIDDistances) {
        boolean areCVEsVeryClose = true;

        for (Object cveIDDistance : cveIDDistances)
            areCVEsVeryClose = areCVEsVeryClose && (Integer) cveIDDistance < 10;

        return areCVEsVeryClose;
    }

    /**
     * If the currentIndex includes a CVE ID, suggests if we should look back or not
     * to extract vulnerability attributes?
     *
     * @param myHTMLElements - elements containing CVE-related text
     * @param currentIndex - index we should start at looking myHTMLElements
     * @return - suggested starting point to look for vulnerability attributes
     */
    private int findStartIndex(Elements myHTMLElements, int currentIndex) {
        int suggestedIndex = currentIndex;

        Element element = myHTMLElements.get(currentIndex);
        if (element != null) {
            // this is a sentence that corresponds to an existing element
            String tag = element.tagName();
            if (tag.startsWith("a") || tag.startsWith("li")) {
                suggestedIndex = currentIndex - 2; // this is a list tag, so look backwards
                if (suggestedIndex < 0)
                    suggestedIndex = 0;
            }
        }
        return suggestedIndex;
    }

    /**
     * if a single tag text includes multiple CVE IDs then split the text according
     * to CVE ID regex (as delimiter) and consider each part as a new sentence.
     * <p>
     * Add the CVE-XXXX-YYYY delimiter either to the end of the split text or to its
     * start. Look if a split text (the prev one) contains newline. If yes,
     * CVE-XXXX-YYYY is assumed to belong to the text that follows it
     *
     * @param tagText - sentence we are tokenizing
     * @return The list of split sentences
     */
    private List<String> tokenizeTagTextAccordingToCVEIDRegex(String tagText) {
        List<String> childSentences = new ArrayList<>();
        Matcher m = Pattern.compile(regexCVEID).matcher(tagText);
        int prevIndex = 0;
        String prevDelimiter = null;
        String prevText;
        String currDelimiter;
        boolean bCVEBelongsToNextText = true;
        String sentenceToAdd;
        int matchCount = 0;

        String shortTextFRomPrevMatch = "";
        while (m.find()) {
            matchCount++;

            currDelimiter = m.group();
            prevText = shortTextFRomPrevMatch + tagText.substring(prevIndex, m.start());
            shortTextFRomPrevMatch = "";
            bCVEBelongsToNextText = (prevText.contains("\n"));

            if (prevIndex == 0) {
                if (bCVEBelongsToNextText)
                    sentenceToAdd = prevText;
                else
                    sentenceToAdd = prevText + currDelimiter;
            } else {
                if (bCVEBelongsToNextText)
                    sentenceToAdd = prevDelimiter + prevText;
                else
                    sentenceToAdd = prevText + currDelimiter;
            }
            prevDelimiter = currDelimiter;
            prevIndex = m.end();

            if (sentenceContainsValuableInfoForCVE(sentenceToAdd, 1))
                childSentences.add(sentenceToAdd);
            else {
                // this is a very short sentence, merge it with next match!
                shortTextFRomPrevMatch = sentenceToAdd + " ";
            }

        }
        // get the text after last delimiter
        String tailText = shortTextFRomPrevMatch + tagText.substring(prevIndex);
        if (bCVEBelongsToNextText)
            sentenceToAdd = prevDelimiter + tailText;
        else
            sentenceToAdd = tailText;

        if (sentenceContainsValuableInfoForCVE(sentenceToAdd, 1))
            childSentences.add(sentenceToAdd);

        log.debug("tokenizeTagTextAccordingToCVEIDRegex: Size: " + childSentences.size() + ", Ignored: " + (matchCount - childSentences.size() + 1) + ", List: " + childSentences.toString().replace("\n", ""));

        return childSentences;
    }

    /**
     * Is this sentence long enough to describe the specified # of CVE ID(s)?
     *
     * @param sentence     - sentence we are checking
     * @param numberOfCVEs - number of supposed CVEs in the sentence
     * @return - true if the sentence is long enough, false otherwise
     */
    private boolean sentenceContainsValuableInfoForCVE(String sentence, int numberOfCVEs) {
        return sentence.length() > (3 * numberOfCVEs * regexCVEID.length());
    }

    /**
     * Search for Version regex X.Y.Z or X.Y in a given sentence. Find the first
     * capitalized word before the regex to extract version info
     *
     * @param sentence - sentence we are searching
     * @return - version info in String format
     */
    private String getPlatformVersion(String sentence) {
        String version = null;

        Pattern pattern = Pattern.compile(regexVersionInfo);
        Matcher matcher = pattern.matcher(sentence);

        if (matcher.find()) {
            version = matcher.group(0);
            if (version == null)
                return null;

            int beginIndex = sentence.lastIndexOf(version);
            int regexStart = beginIndex;
            beginIndex = beginIndex > 0 ? beginIndex - 1 : 0;

            /*
              Find the first capitalized word before the regex to extract version info
             */
            boolean firstCaps = false;
            boolean spaceAfterCaps = false;
            while (!(firstCaps && spaceAfterCaps)) {
                if (beginIndex == 0)
                    break;
                if (!firstCaps)
                    firstCaps = Character.isUpperCase(sentence.charAt(beginIndex));
                if (firstCaps)
                    spaceAfterCaps = (sentence.charAt(beginIndex) == ' ');

                // break if \n
                if (sentence.charAt(beginIndex) == '\n') {
                    beginIndex++;
                    break;
                }
                beginIndex--;

            }
            beginIndex++; // skip space
            version = sentence.substring(beginIndex, regexStart + version.length());

            /*
              if the previous word is not a product name? May be like at/in/of etc. still
              return null
             */
            if (regexStart - beginIndex < 5)
                return null;
        }
        return version;
    }

    /**
     * find unique CVE IDs in a given string of content
     * @param strContent - content we are searching
     * @param parsingASentence - are we parsing a sentence or a whole document?
     * @return - a map of unique CVE IDs and their distance from the previous CVE ID
     */
    private Map<String, Integer> getUniqueCVEIDs(String strContent, boolean parsingASentence) {
        Pattern pattern = Pattern.compile(regexCVEID);
        Matcher matcher = pattern.matcher(strContent);

        /*
          The hash map key is the CVE ID and the value is its distance from the CVE ID
          before it. We use this proximity info to see if we have something like
          "CVE-2016-2108, CVE-2016-2107, CVE-2016-2105, CVE-2016-2106" in a sentence.
          If yes the sentence context is assumed to be related to all CVE IDs in the
          sentence
         */
        Map<String, Integer> cveIDs = new HashMap<>();

        int distance = 0;
        int prevIndex = 0;
        while (matcher.find()) {
            if (parsingASentence) {
                if (prevIndex == 0)
                    distance = 0; // first match
                else
                    distance = matcher.start() - prevIndex;
                prevIndex = matcher.end();
            }
            cveIDs.put(matcher.group(0), distance);
        }
        return cveIDs;
    }

    /**
     * Find the first CVE ID in a given string of content
     * @param strContent - string we are searching
     * @return - first CVE ID in the string
     */
    private String getFirstCveIdFromString(String strContent) {
        String cveID = null;
        Pattern pattern = Pattern.compile(regexCVEID);
        Matcher matcher = pattern.matcher(strContent);
        if (matcher.find())
            cveID = matcher.group(0);
        return cveID;
    }
}
