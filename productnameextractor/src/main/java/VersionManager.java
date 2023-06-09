import model.ProductVersion;
import model.VersionRange;
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
     * TODO: Docstring
     * @param versionWords
     */
    public void processVersions(String[] versionWords) {

        // Clear existing range set if not empty
        final int numRanges = this.versionRanges.size();
        if (numRanges > 0) {
            logger.info("Clearing {} old version ranges", numRanges);
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

                //Through case - "1.2.5 through 2.4.1"
                if(throughFlag){
                    String rangeString = versionWords[i - 2] + " through " + versionWord;
                    addRangeFromString(rangeString);
                    throughFlag = false;

                //Before case - "before 3.7.1"
                }else if(beforeFlag){
                    String rangeString = "before " + versionWord;
                    addRangeFromString(rangeString);
                    beforeFlag = false;

                //After case - "after 3.7.1"
                }else if(afterFlag){
                    String rangeString = "after " + versionWord;
                    addRangeFromString(rangeString);
                    afterFlag = false;

                //Standalone version - "1.5.6"
                }else {
                    addRangeFromString(versionWord);
                }
            }else if(versionWord.equals("before")){
                beforeFlag = true;
            }else if(versionWord.equals("after")){
                afterFlag = true;
            }else if(versionWord.equals("through")){
                throughFlag = true;
            }
            i++;
        }
    }

    private static boolean isVersion(String version) {
        if(version.contains(",")) logger.warn("VERSION '{}' CONTAINED UNEXPECTED CHARACTER ','", version);
        return VERSION_PATTERN.matcher(version).matches();
    }

    private static void formatVersions(String[] versionWords){
        for(int i = 0; i < versionWords.length; i++){
            versionWords[i] = versionWords[i].replace(",","");
            versionWords[i] = versionWords[i].replace(".x","");
        }
    }

}
