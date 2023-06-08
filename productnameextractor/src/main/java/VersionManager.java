import model.ProductVersion;

import java.util.HashSet;

public class VersionManager {
    private final HashSet<VersionRange> versionRanges;

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

        public VersionRange(String versionRangeString) {
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

    public void addRangeFromString(String rangeString) {
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
}
