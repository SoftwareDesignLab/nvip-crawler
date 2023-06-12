import model.cpe.ProductVersion;
import model.cpe.VersionRange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashSet;
import java.util.regex.Pattern;

public class VersionManager {
    private final HashSet<VersionRange> versionRanges;
    // Regex101: https://regex101.com/r/cy9Hp3/1
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
     *
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

                //Through case - "1.2.5 through 2.4.1" "8.6 to 9.1"
                if(throughFlag){
                    if(isVersion(versionWords[i - 2])) {
                        String rangeString = versionWords[i - 2] + " through " + versionWord;
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
            }

            //Handles "3.9.5+" case
            if(versionWords[i].charAt(versionWords[i].length() - 1) == '+' && isVersion(versionWords[i].substring(0,(versionWords[i].length()) - 1))){
                addRangeFromString("after " + versionWords[i].substring(0,(versionWords[i].length()) - 1));
            }

            i++;
        }
    }

    /**
     * Function to determine whether a string is a version or not using regex matcher
     * Regex101: https://regex101.com/r/cy9Hp3/1
     * @param version
     * @return true if version, false if not
     */
    public static boolean isVersion(String version) {
        if(version.contains(",")) logger.warn("VERSION '{}' CONTAINED UNEXPECTED CHARACTER ','", version);
        return VERSION_PATTERN.matcher(version).matches();
    }

    /**
     * Function to format version words into acceptable composition for isVersion() function
     * Handles cases such as "1.7," or "v1.2" to turn them into "1.7" and "1.2"
     * @param versionWords
     */
    public void formatVersions(String[] versionWords){
        for(int i = 0; i < versionWords.length; i++){
            versionWords[i] = versionWords[i].replace(",","");
            versionWords[i] = versionWords[i].replace(".x","");
            versionWords[i] = versionWords[i].replace("v","");
            versionWords[i] = versionWords[i].replace(")","");
            versionWords[i] = versionWords[i].replace("(","");

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
