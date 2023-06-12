package model.cpe;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Data class to represent a version of a product. This class also contains static functionality
 * to manipulate ProductVersion instances.
 */
public class ProductVersion implements Comparable<ProductVersion> {
    private final int[] versionParts;
    // Regex101: https://regex101.com/r/cy9Hp3/1
    private static final Pattern VERSION_PATTERN = Pattern.compile("^((?:[0-9]\\.?)*)$");
    private final static Logger logger = LogManager.getLogger(ProductVersion.class);


    public ProductVersion(String versionString) throws IllegalArgumentException {
        // Ensure provided version is valid
        if(!isVersion(versionString))
            throw new IllegalArgumentException("Failed to create ProductVersion from String '" + versionString + "'");

        // Split version into parts
        try {
            this.versionParts = Arrays.stream(versionString.split("\\.")).mapToInt(Integer::parseInt).toArray();
        } catch (NumberFormatException e) {
            logger.error("Failed to create ProductVersion from String '{}'", versionString);
            throw e;
        }
    }

    private ProductVersion(int[] versionParts) {
        this.versionParts = versionParts;
    }

    private boolean isVersion(String version) {
        if(version.contains(",")) logger.warn("VERSION '{}' CONTAINED UNEXPECTED CHARACTER ','", version);
        return VERSION_PATTERN.matcher(version).matches();
    }

    @Override
    public int compareTo(@NotNull ProductVersion o) {
        // Extract parts lists
        int[] parts = this.versionParts;
        int[] otherParts = o.versionParts;
        int shortest = Math.min(parts.length, otherParts.length);
        for (int i = 0; i < shortest; i++) {
            // Extract part values
            int vp = parts[i];
            int otherVp = otherParts[i];

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
        return String.join(".", Arrays.stream(this.versionParts).mapToObj(Integer::toString).toArray(String[]::new));
    }
}
