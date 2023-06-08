import model.ProductVersion;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashSet;
import java.util.regex.Pattern;

public class VersionManager {
    private final HashSet<VersionRange> versionRanges;
    // Regex101: https://regex101.com/r/cy9Hp3/1
    private static final Pattern VERSION_PATTERN = Pattern.compile("^((?:[0-9]\\.?)*)$");
    private final static Logger logger = LogManager.getLogger(VersionManager.class);

    public VersionManager() {
        this.versionRanges = new HashSet<>();
    }

    public enum RangeType {
        BEFORE,
        THROUGH,
        AFTER,
        EXACT;

        public static RangeType fromString(String rangeTypeString) {
            return RangeType.valueOf(rangeTypeString.toUpperCase().trim());
        }
    }

    public class VersionRange {
        private final ProductVersion version1;
        private final ProductVersion version2;
        private final RangeType type;

        public VersionRange(String versionRangeString) throws IllegalArgumentException {
            // Extract data from params
            final String[] versionData = versionRangeString.split(" ");

            // Assign data to class appropriately
            switch (versionData.length) {
                case 1: // "1.2.3"
                    this.type = RangeType.EXACT;
                    this.version1 = new ProductVersion(versionData[0]);
                    this.version2 = null;
                    break;
                case 2: // "before 1.2.3", "after 1.2.3"
                    this.type = RangeType.fromString(versionData[0]);
                    this.version1 = new ProductVersion(versionData[1]);
                    this.version2 = null;
                    break;
                case 3: // "1.2.3 through 3.4.5"
                    this.type = RangeType.fromString(versionData[1]);
                    this.version1 = new ProductVersion(versionData[0]);
                    this.version2 = new ProductVersion(versionData[2]);
                default:
                    throw new IllegalArgumentException("Could not initilize VersionRange with the given arguments.");
            }
        }
        public VersionRange(ProductVersion version1, ProductVersion version2, RangeType type) {
            this.version1 = version1;
            this.version2 = version2;
            this.type = type;
        }

        public RangeType getType() {
            return type;
        }

        public boolean withinRange(ProductVersion testVersion) {
            switch (this.type) {
                case BEFORE:
                    return version1.compareTo(testVersion) <= 0;
                case THROUGH:
                    return version1.compareTo(testVersion) >= 0 && version2.compareTo(testVersion) <= 0;
                case AFTER:
                    return version1.compareTo(testVersion) >= 0;
                case EXACT:
                    return version1.equals(testVersion);
                default:
                    return false;
            }
        }
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

    // TODO: Docstring
    public void processVersions(String[] versionWords) {
        // Clear existing range set if not empty
        final int numRanges = this.versionRanges.size();
        if(numRanges > 0) {
            logger.info("Clearing {} old version ranges", numRanges);
            this.versionRanges.clear();
        }

        // Iterate over versions
        String lastVersion = null;
        for (int i = 0; i < versionWords.length; i++) {
            String version = versionWords[i];
            // If version is version, add it
            if (isVersion(version)) addRangeFromString(version);
            else {
                // Ensure next element exists
                if (i + 1 >= versionWords.length) {
                    logger.warn("Non-version '{}' is the last version to process and has no succeeding element to reference", version);
                    continue;
                }

                // Get next element
                final String nextVersion = versionWords[i+1];

                // Build version range string
                final StringBuilder versionRangeString = new StringBuilder();
                if(lastVersion != null) versionRangeString.append(lastVersion).append(" ");
                versionRangeString.append(lastVersion).append(" ");
                versionRangeString.append(nextVersion);

                try {
                    // Add range to VersionManager
                    this.addRangeFromString(versionRangeString.toString());
                } catch (IllegalArgumentException e) {
                    logger.error("Failed to add version range '{}' from string: {}", versionRangeString, e.toString());
                }
            }

            // Store last version value
            lastVersion = version;
        }

        logger.info("Done processing {} version words into {} version ranges", versionWords.length, versionRanges.size());
    }

    private static boolean isVersion(String version) {
        if(version.contains(",")) logger.warn("VERSION '{}' CONTAINED UNEXPECTED CHARACTER ','", version);
        return VERSION_PATTERN.matcher(version).matches();
    }
}
