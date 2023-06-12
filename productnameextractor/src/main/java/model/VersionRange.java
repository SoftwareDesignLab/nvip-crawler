package model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionRange {
    private final ProductVersion version1;
    private final ProductVersion version2;
    private final RangeType type;
    private final static Logger logger = LogManager.getLogger(VersionRange.class);

    public enum RangeType {
        BEFORE,
        THROUGH,
        AFTER,
        EXACT;

        public static RangeType fromString(String rangeTypeString) {
            return RangeType.valueOf(rangeTypeString.toUpperCase().trim());
        }
    }

    public VersionRange(String versionRangeString) throws IllegalArgumentException {
        // Extract data from params
        final String[] versionData = versionRangeString.split(" ");

        try {
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
                    break;
                default:
                    throw new IllegalArgumentException("Could not initialize VersionRange with the given arguments.");
            }
        } catch (Exception e) {
            logger.error("Failed to create VersionRange: {}", e.toString());
            throw e;
        }
    }

    public RangeType getType() {
        return type;
    }
    public ProductVersion getVersion1() {
        return this.version1;
    }
    public ProductVersion getVersion2() {
        return this.version2;
    }

    public boolean withinRange(ProductVersion testVersion) {
        switch (this.type) {
            case BEFORE:
                return version1.compareTo(testVersion) >= 0;
            case THROUGH:
                return version1.compareTo(testVersion) <= 0 && version2.compareTo(testVersion) >= 0;
            case AFTER:
                return version1.compareTo(testVersion) <= 0;
            case EXACT:
                return version1.equals(testVersion);
            default:
                return false;
        }
    }

    @Override
    public String toString() {
        if(this.type == RangeType.THROUGH){
            return version1.toString() + " " + RangeType.THROUGH + " " + version2.toString();
        }
        return this.type + " " + version1.toString();
    }
}
