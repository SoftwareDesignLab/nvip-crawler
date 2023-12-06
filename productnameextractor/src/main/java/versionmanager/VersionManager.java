package versionmanager;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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

import model.cpe.ProductVersion;
import model.cpe.VersionRange;

import java.util.HashSet;
import java.util.regex.Pattern;

/**
 * Controller class for processing non-specific versions into version ranges
 * for comparison.
 *
 * @author Dylan Mulligan
 * @author Paul Vickers
 */
public class VersionManager {
    // Regex101: https://regex101.com/r/y88Gsj/1
    private final static Pattern VERSION_PATTERN = Pattern.compile("^((?:\\d{1,5}\\.)*\\d{1,5})$");
    private final HashSet<VersionRange> versionRanges;
    public VersionManager() {
        versionRanges = new HashSet<>();
    }

    public HashSet<VersionRange> getVersionRanges() {
        return versionRanges;
    }

    public void addRangeFromString(String rangeString) throws IllegalArgumentException {
        versionRanges.add(new VersionRange(rangeString));
    }

    /**
     * Tests whether a given version "is affected" (within) any of the ranges
     * within this.versionRanges.
     *
     * @param version version to test
     * @return result of test
     */
    public boolean isAffected(ProductVersion version) {
        // Default to not affected
        boolean affected = false;

        // If any range validates, set to true and break loop
        for (VersionRange vr : versionRanges) {
            if (vr.withinRange(version)) {
                affected = true;
                break;
            }
        }

        // Return affected result
        return affected;
    }

    /**
     * Function to take in a list of versionWords from a product and configure them
     * into VersionRange objects to be added to versionRanges
     *
     * For example, a list of ["before", "1.8.9", "1.9", "9.6+"]
     * would become version ranges [BEFORE 1.8.9, EXACT 1.9, AFTER 9.6]
     *
     * @param versionWords list of product version words derived from NER model
     */
    public void processVersions(String[] versionWords) {

        //Format versions into acceptable format - no "v3.6" or "5.7,"
        formatVersionWords(versionWords);

        boolean beforeFlag = false;
        boolean afterFlag = false;
        boolean throughFlag = false;
        int i = 0;

        while (i < versionWords.length) {
            //Current version word
            String versionWord = versionWords[i];

            if (isVersion(versionWord) && !versionWord.isEmpty()) {
                //Standalone version - "1.5.6"
                if (!afterFlag && !beforeFlag && !throughFlag) {
                    addRangeFromString(versionWord);
                }

                //Through case - "1.2.5 through 2.4.1" "8.6 to 9.1" "through 8.6"
                if (throughFlag) {
                    String prevVersion = "";
                    if(i - 2 >= 0){
                        prevVersion = versionWords[i - 2];
                    }
                    if (isVersion(prevVersion)) {
                        String rangeString = prevVersion + " through " + versionWord;
                        addRangeFromString(rangeString);
                    } else {
                        String rangeString = "before " + versionWord;
                        addRangeFromString(rangeString);
                    }
                    throughFlag = false;
                }

                //Before case - "before 3.7.1"
                if (beforeFlag) {
                    String rangeString = "before " + versionWord;
                    addRangeFromString(rangeString);
                    beforeFlag = false;
                }

                //After case - "after 3.7.1"
                if (afterFlag) {
                    String rangeString = "after " + versionWord;
                    addRangeFromString(rangeString);
                    afterFlag = false;
                }

            //If word is "before", "after", or "through", sets appropriate flag
            } else if (versionWord.equals("before")) {
                beforeFlag = true;
            } else if (versionWord.equals("after")) {
                afterFlag = true;
            } else if (versionWord.equals("through")) {
                throughFlag = true;

            //Handles "1.8 to 4.2", "prior to 3.4", "prior 1.3"
            } else if (versionWord.equals("prior")) {
                beforeFlag = true;
            } else if (versionWord.equals("to") && !beforeFlag) {
                throughFlag = true;

            //Handles "6.3.1 and earlier" "6.3.1 version and prior versions" as well as after and later
            } else if (versionWord.equals("and")) {
                try {
                    if (versionWords[i + 1].equals("earlier") || versionWords[i + 1].equals("prior")) {
                        int j = i - 1;
                        if (versionWords[j].endsWith(".x")) {
                            versionWords[j] = versionWords[j].replace("x", "9");
                        }
                        while (!isVersion(versionWords[j])) {
                            j -= 1;
                        }
                        addRangeFromString("before " + versionWords[j]);
                    }
                } catch (IndexOutOfBoundsException e) {
                    break;
                }
                try {
                    if (versionWords[i + 1].equals("after") || versionWords[i + 1].equals("later")) {
                        int j = i - 1;
                        if (versionWords[j].endsWith(".x")) {
                            versionWords[j] = versionWords[j].replace(".x", "");
                        }
                        while (!isVersion(versionWords[j])) {
                            j -= 1;
                        }
                        addRangeFromString("after " + versionWords[j]);

                    }
                } catch (IndexOutOfBoundsException e) {
                    break;
                }

            //Handles "between 1.5 and 2.8" case
            } else if (versionWord.equals("between")) {
                String version1 = null;
                String version2 = null;
                boolean bothFound = false;
                try {
                    while (!bothFound) {
                        i++;
                        String possibleVersion = versionWords[i];

                        //Handle "between 8.x and 10" or "between 5.2 and 6.x"
                        if (possibleVersion.endsWith(".x")) {
                            String removedX = possibleVersion.replace(".x", "");
                            String replacedX = removedX + ".9";
                            if (version1 == null) {
                                //In case "between" word is random, account for 5.x range
                                addRangeFromString(removedX + " through " + replacedX);
                                possibleVersion = removedX;
                            } else {
                                possibleVersion = replacedX;
                            }
                        }
                        if (isVersion(possibleVersion)) {
                            if (version1 == null) {
                                version1 = possibleVersion;

                                //in case no other version is found
                                addRangeFromString(version1);
                            } else {
                                version2 = possibleVersion;
                                bothFound = true;
                            }
                        }
                    }

                    addRangeFromString(version1 + " through " + version2);
                } catch (IndexOutOfBoundsException e) {
                    break;
                }

            //Handles "3.9+" case
            } else if (versionWord.endsWith("+")) {
                versionWord = versionWord.replace("+", "");
                //"3.9.x+" becomes "3.9+"
                if (versionWord.endsWith(".x")) {
                    versionWord = versionWord.replace(".x", "");
                }
                if(isVersion(versionWord)){
                    addRangeFromString("after " + versionWord);
                }

            //Handles "<1.2.4" case and "<, 1.2.4" case where 1.2.4 is the next word in line
            } else if (versionWord.startsWith("<")) {
                //"<2.x" becomes "<2.9"
                if (versionWord.endsWith(".x")) {
                    versionWord = versionWord.replace("x", "9");
                }
                if (isVersion(versionWord.substring(1))) {
                    addRangeFromString("before " + versionWord.substring(1));
                } else if (versionWord.length() == 1) {
                    beforeFlag = true;
                }

            //Handles ">1.2.4" case and ">, 1.2.4" case where 1.2.4 is the next word in line
            } else if (versionWord.startsWith(">")) {
                //>2.x becomes >2
                if (versionWord.endsWith(".x")) {
                    versionWord = versionWord.replace(".x", "");
                }
                if (isVersion(versionWord.substring(1))) {
                    addRangeFromString("after " + versionWord.substring(1));
                } else if (versionWord.length() == 1) {
                    afterFlag = true;
                }

            //Have to make sure "before 5.x" becomes "before 5.9"
            //and standalone "8.2.x" works where "8.2.x" becomes 8.2 through 8.2.9
            } else if (versionWord.endsWith(".x")) {
                String removedX = versionWord.substring(0, versionWord.length() - 2);
                String replacedX = removedX + ".9";

                //"before 5.x" becomes "before 5.9"
                if (beforeFlag) {
                    addRangeFromString("before " + replacedX);
                    beforeFlag = false;
                }

                //"after 5.x" becomes "after 5"
                else if (afterFlag) {
                    addRangeFromString("after " + removedX);
                    afterFlag = false;
                }

                //"4.2.3 through 5.x" becomes "4.2.3 through 5.9"
                else if (throughFlag) {
                    String prevVersion = "";
                    if(i - 2 >= 0){
                        prevVersion = versionWords[i - 2];
                    }
                    if (isVersion(prevVersion)) {
                        String rangeString = prevVersion + " through " + replacedX;
                        addRangeFromString(rangeString);
                    } else {
                        String rangeString = "before " + replacedX;
                        addRangeFromString(rangeString);
                    }
                    throughFlag = false;

                //Standalone "5.x" version becomes "5.0 through 5.9"
                } else {
                    if(isVersion(removedX) && isVersion(replacedX)){
                        addRangeFromString(removedX + " through " + replacedX);
                    }
                }
            }

            i++;
        }
    }

    /**
     * Tests whether a string is a version or not using regex matcher
     *
     * @param version version to test
     * @return result of test
     */
    public static boolean isVersion(String version) {
        if (version.isEmpty()) return false;
        return VERSION_PATTERN.matcher(version).matches();
    }

    /**
     * Calls ProductVersion.formatVersionWord() to format version words
     * into acceptable composition for isVersion() function
     * Handles cases such as "1.7," or "v1.2" to turn them into "1.7" and "1.2"
     *
     * @param versionWords array of words to format
     */
    public void formatVersionWords(String[] versionWords) {
        for (int i = 0; i < versionWords.length; i++) {
            if (versionWords[i] == null) continue;
            versionWords[i] = ProductVersion.formatVersionWord(versionWords[i]);
        }
    }
}
