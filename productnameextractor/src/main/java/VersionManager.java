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

import model.cpe.ProductVersion;
import model.cpe.VersionRange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
    private final HashSet<VersionRange> versionRanges;
    // Regex101: https://regex101.com/r/cy9Hp3/1

    //Set of words to be protected from removing characters
    private final static HashSet<String> protectedWords;
    static{
        protectedWords = new HashSet<>();
        protectedWords.add("earlier");
        protectedWords.add("after");
        protectedWords.add("and");
        protectedWords.add("version");
        protectedWords.add("before");
        protectedWords.add("through");
        protectedWords.add("prior");
        protectedWords.add("to");
        protectedWords.add("versions");
    }
    private final static Pattern VERSION_PATTERN = Pattern.compile("^((?:[0-9]\\.?)*)$");
    private final static Logger logger = LogManager.getLogger(VersionManager.class);

    public VersionManager() {
        this.versionRanges = new HashSet<>();
    }

    public HashSet<VersionRange> getVersionRanges(){
        return versionRanges;
    }

    public void addRangeFromString(String rangeString) throws IllegalArgumentException {
        this.versionRanges.add(new VersionRange(rangeString));
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
        for (VersionRange vr : this.versionRanges){
            if(vr.withinRange(version)) {
                affected = true;
                break;
            }
        }

        // Return affected result
        return affected;
    }

    /**
     * Function to take in a list of versionWords from a product and configure them
     * into VersionRange objects to be added to this.versionRanges
     *
     * For example, a list of ["before", "1.8.9", "1.9", "9.6+"]
     * would become version ranges [BEFORE 1.8.9, EXACT 1.9, AFTER 9.6]
     * TODO: handle between case
     * @param versionWords list of product version words derived from NER model
     */
    public void processVersions(String[] versionWords) {

        // Clear existing range set if not empty
        final int numRanges = this.versionRanges.size();
        if (numRanges > 0) {
            this.versionRanges.clear();
        }

        //Format versions into acceptable format - no "3.7.x" or "5.7,"
        formatVersions(versionWords);

        boolean beforeFlag = false;
        boolean afterFlag = false;
        boolean throughFlag = false;
        int i = 0;

        while(i < versionWords.length){
            String versionWord = versionWords[i];
            if(isVersion(versionWord) && !versionWord.isEmpty()) {
                //Standalone version - "1.5.6"
                if(!afterFlag && !beforeFlag && !throughFlag){
                    addRangeFromString(versionWord);
                }

                //Through case - "1.2.5 through 2.4.1" "8.6 to 9.1" "through 8.6"
                if(throughFlag){
                    if(isVersion(versionWords[i - 2])) {
                        String rangeString = versionWords[i - 2] + " through " + versionWord;
                        addRangeFromString(rangeString);
                    }else{
                        String rangeString = "before " + versionWord;
                        addRangeFromString(rangeString);
                    }
                    throughFlag = false;
                }

                //Before case - "before 3.7.1"
                if(beforeFlag){
                    String rangeString = "before " + versionWord;
                    addRangeFromString(rangeString);
                    beforeFlag = false;
                }

                //After case - "after 3.7.1"
                if(afterFlag) {
                    String rangeString = "after " + versionWord;
                    addRangeFromString(rangeString);
                    afterFlag = false;
                }

            //If word is "before", "after", or "through", sets appropriate flag
            }else if(versionWord.equals("before")){
                beforeFlag = true;
            }else if(versionWord.equals("after")){
                afterFlag = true;
            }else if(versionWord.equals("through")){
                throughFlag = true;

            //Handles "1.8 to 4.2", "prior to 3.4", "prior 1.3"
            }else if(versionWord.equals("prior")){
                beforeFlag = true;
            }else if(versionWord.equals("to") && !beforeFlag){
                throughFlag = true;

            //Handles "6.3.1 and earlier"
            }else if(versionWord.equals("and")){
                if(versionWords[i + 1].equals("earlier")){
                    if(isVersion(versionWords[i - 1])) addRangeFromString("before " + versionWords[i - 1]);
                }
            }

            //Handles "3.9.5+" case
            if(versionWords[i].charAt(versionWords[i].length() - 1) == '+' && isVersion(versionWords[i].substring(0,(versionWords[i].length()) - 1))){
                addRangeFromString("after " + versionWords[i].substring(0,(versionWords[i].length()) - 1));
            }

            //Handles "<1.2.4" case
            if(versionWords[i].charAt(0) == '<' && isVersion(versionWords[i].substring(1))){
                addRangeFromString("before " + versionWords[i].substring(1));
            }

            //Handles ">1.2.4" case
            if(versionWords[i].charAt(0) == '>' && isVersion(versionWords[i].substring(1))){
                addRangeFromString("after " + versionWords[i].substring(1));
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
        return VERSION_PATTERN.matcher(version).matches();
    }

    /**
     * Function to format version words into acceptable composition for isVersion() function
     * Handles cases such as "1.7," or "v1.2" to turn them into "1.7" and "1.2"
     *
     * @param versionWords array of words to format
     */
    public void formatVersions(String[] versionWords){
        for(int i = 0; i < versionWords.length; i++){
            //If word is protected, continue
            if(protectedWords.contains(versionWords[i])) continue;

            //Remove junk characters
            versionWords[i] = versionWords[i].replace(",","");
            versionWords[i] = versionWords[i].replace(".x","");
            versionWords[i] = versionWords[i].replace("v","");
            versionWords[i] = versionWords[i].replace(")","");
            versionWords[i] = versionWords[i].replace("(","");
            versionWords[i] = versionWords[i].replace("a","");
            versionWords[i] = versionWords[i].replace("b","");
            versionWords[i] = versionWords[i].replace("c","");
            versionWords[i] = versionWords[i].replace(":","");

            //Removes period at the end of a version "1.9.2." to "1.9.2"
            if(versionWords[i].charAt((versionWords[i].length()) - 1) == '.'){
                versionWords[i] = versionWords[i].substring(0, versionWords[i].length() - 1);
            }

            //Remove any "1.2.3a" to be "1.2.3", makes sure to not affect "after" word
            if(!versionWords[i].equals("after")){
                versionWords[i] = versionWords[i].replace("a","");
            }

            //Same as above but for 'b'
            if(!versionWords[i].equals("before")){
                versionWords[i] = versionWords[i].replace("b","");
            }
        }
    }
}
