package model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import utils.UtilHelper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class ProductVersion implements Comparable<ProductVersion> {
    private final String[] versionParts;
    // Regex101: https://regex101.com/r/cy9Hp3/1
    private static final Pattern VERSION_PATTERN = Pattern.compile("^((?:[0-9]\\.?)*)$");
    private final static Logger logger = LogManager.getLogger(ProductVersion.class);


    public ProductVersion(String versionString) {
        // Ensure provided version is valid
        assert isVersion(versionString);

        // Split version into parts
        this.versionParts = versionString.split("\\.");
    }

    private ProductVersion(String[] versionParts) {
        this.versionParts = versionParts;
    }

    private boolean isVersion(String version) {
        if(version.contains(",")) logger.warn("VERSION '{}' CONTAINED UNEXPECTED CHARACTER ','", version);
        return VERSION_PATTERN.matcher(version).matches();
    }

    public ProductVersion getBaseVersion() {
        if(versionParts.length > 1) {
            return new ProductVersion(Arrays.copyOfRange(versionParts, 0, versionParts.length - 1));
        } else return this;
    }

    public List<ProductVersion> interpolate(ProductVersion o) {
        // Compare 'this' and 'o' to find greater version
        final int comparison = this.compareTo(o);

        // Select the correct 'first' and 'second' versions (earlier, later)
        ProductVersion firstVersion, secondVersion;
        switch (comparison) {
            // 'o' is greater (1.2<1.3; 1.2<1.2.1)
            case -1:
                firstVersion = this;
                secondVersion = o;
                break;
            // 'this' is greater (1.3>1.2; 1.2.1>1.2)
            case 1:
                firstVersion = o;
                secondVersion = this;
                break;
            // equal versions (1.3==1.3)
            default: // default instead of case 0 so firstVersion and secondVersion are always initialized
                firstVersion = this;
                secondVersion = firstVersion;
                break;

        }

        // Find the specificity of each version (1.2 = 2 spec, 1.2.3.4 = 4 spec)
        final int firstSpec = firstVersion.versionParts.length;
        final int secondSpec = secondVersion.versionParts.length;

        // Iterate over range and add values to interpolatedVersions
        return interpolateVersions(firstVersion, secondVersion, firstSpec, secondSpec);
    }

    /**
     * Interpolates versions between the given first and second versions based on their specificities.
     *
     * @param firstVersion  The earlier version as a ProductVersion object
     * @param secondVersion The later version as a ProductVersion object
     * @param firstSpec     The specificity of the first version
     * @param secondSpec    The specificity of the second version
     * @return A list of interpolated versions between the first and second versions
     */
    public static List<ProductVersion> interpolateVersions(ProductVersion firstVersion, ProductVersion secondVersion, int firstSpec, int secondSpec) {
        String[] firstParts = firstVersion.versionParts;
        String[] secondParts = secondVersion.versionParts;

        List<ProductVersion> interpolatedVersions = new ArrayList<>();

        int specDifference = Math.abs(secondSpec - firstSpec);
        int[] specCounts = new int[specDifference];

        // Differentiate between long and short versions, standardizing the length of both arrays
        final String[] longerParts;
        final String[] shorterParts;
        boolean firstShorter;
        if (firstParts.length > secondParts.length) {
            firstShorter = false;
            longerParts = firstParts;
            shorterParts = new String[longerParts.length];
            System.arraycopy(secondParts, 0, shorterParts, 0, secondParts.length);
            secondParts = shorterParts;
        } else {
            firstShorter = true;
            longerParts = secondParts;
            shorterParts = new String[longerParts.length];
            System.arraycopy(firstParts, 0, shorterParts, 0, firstParts.length);
            firstParts = shorterParts;
        }

        // Calculate specCounts
        for (int i = 0; i < specDifference; i++) {
            specCounts[i] = roundUpToNearestTen(Integer.parseInt(longerParts[specDifference + i]));
            // Fill shorter version with max values (specCounts)
            if(firstShorter) firstParts[specDifference + i] = String.valueOf(specCounts[i]);
            else secondParts[specDifference + i] = String.valueOf(specCounts[i]);
        }

        // Interpolate versions with the given version info
        interpolateVersionsRecursive(interpolatedVersions, firstParts, secondParts, specCounts, new String[Math.max(firstSpec, secondSpec)], specDifference, 0);

        // Return list of interpolated versions
        return interpolatedVersions;
    }

    /**
     * Recursively interpolates versions between the first and second versions based on specificities and specCounts.
     *
     * @param interpolatedVersions The list to store the interpolated versions
     * @param firstParts           The array of version parts of the first version
     * @param secondParts          The array of version parts of the second version
     * @param specCounts           The array containing the number of interpolated versions for each level of specificity
     * @param currentVersion       The current version being constructed
     * @param currentSpec          The current level of specificity
     */
    private static void interpolateVersionsRecursive(List<ProductVersion> interpolatedVersions, String[] firstParts, String[] secondParts, int[] specCounts, String[] currentVersion, int specDifference, int currentSpec) {
        if (currentSpec == currentVersion.length) {
            interpolatedVersions.add(new ProductVersion(currentVersion.clone()));
        } else {
            if (currentSpec < specDifference) {
                currentVersion[currentSpec] = firstParts[currentSpec];
                interpolateVersionsRecursive(interpolatedVersions, firstParts, secondParts, specCounts, currentVersion, specDifference, currentSpec + 1);
            } else {
                int count = specCounts[currentSpec - specDifference];

                for (int i = 1; i <= count; i++) {
                    double ratio = (double) i / count;

                    if (currentSpec < currentVersion.length) {

                        int interpolatedPart = interpolatePart(firstParts[currentSpec], secondParts[currentSpec], ratio);
                        currentVersion[currentSpec] = Integer.toString(interpolatedPart);
                        interpolateVersionsRecursive(interpolatedVersions, firstParts, secondParts, specCounts, currentVersion, specDifference, currentSpec + 1);
                    }
                }
            }
        }
    }


    /**
     * Calculates the number of versions to be interpolated for a specific level of specificity.
     *
     * @param versionParts The array of version parts
     * @param spec         The level of specificity
     * @return The number of versions to be interpolated
     */
    private static int getVersionCount(String[] versionParts, int spec) {
        if (spec >= versionParts.length) {
            return 1;
        }

        String versionPart = versionParts[spec];
        int partValue = Integer.parseInt(versionPart);

        return Math.max(roundUpToNearestTen(partValue), 1);
    }

    /**
     * Rounds up a value to the nearest ten.
     *
     * @param value The value to be rounded
     * @return The rounded value
     */
    private static int roundUpToNearestTen(int value) {
        return (int) (Math.ceil(value / 10.0) * 10);
    }

    /**
     * Interpolates a version part between the first and second part based on a given ratio.
     *
     * @param firstPart  The first version part
     * @param secondPart The second version part
     * @param ratio      The interpolation ratio
     * @return The interpolated version part
     */
    private static int interpolatePart(String firstPart, String secondPart, double ratio) {
        // Define int vars
        int firstValue, secondValue;

        // Try to parse and default to 0 if fails
        try { firstValue = Integer.parseInt(firstPart); } catch (NumberFormatException ignored) { firstValue = 0; }
        try { secondValue = Integer.parseInt(secondPart); } catch (NumberFormatException ignored) { secondValue = 0; }

        // Return interpolated value
        return (int) (firstValue + (secondValue - firstValue) * ratio);
    }

    @Override
    public int compareTo(@NotNull ProductVersion o) {
        // Extract parts lists
        String[] parts = this.versionParts;
        String[] otherParts = o.versionParts;
        int shortest = Math.min(parts.length, otherParts.length);
        for (int i = 0; i < shortest; i++) {
            // Extract part values
            int vp = Integer.parseInt(parts[i]);
            int otherVp = Integer.parseInt(otherParts[i]);

            // If greater/less, return comparison result
            if(vp < otherVp) return -1;
            else if(otherVp < vp) return 1;
            // Otherwise, continue with for loop
        }
        // If we reach the end of the loop without returning, parts were equal
        // If the versions differ in length, the longer one is greater, otherwise, they are equal
        if(parts.length == otherParts.length) return 0;
        else return parts.length > otherParts.length ? 1 : -1;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProductVersion that = (ProductVersion) o;
        return Arrays.equals(versionParts, that.versionParts);
    }

    @Override
    public String toString() {
        return "ProductVersion{" +
                "versionParts=" + Arrays.toString(versionParts) +
                '}';
    }

    public static void main(String[] args) {
        ProductVersion v1 = new ProductVersion("1.2.5.13");
        ProductVersion v2 = new ProductVersion("1.3");
        List<ProductVersion> versions = v1.interpolate(v2);
        versions.forEach(logger::info);
    }
}
