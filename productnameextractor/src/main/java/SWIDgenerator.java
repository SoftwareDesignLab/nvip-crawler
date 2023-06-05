package main.java;
import java.util.List;

/**
 * SWIDgenerator class for generating SWID tags
 * @author Richard
 */
public class SWIDgenerator {
    private static final String SWID_PREFIX = "swid:"; // Prefix for SWID tag

/**
     * Generates SWID tag based on product information
     * @param productItem ProductItem object
     * @return String SWID tag
     */
    public String generateSWID(ProductItem productItem) {
        // Generate SWID based on product information
        String name = productItem.getName();
        List<String> versions = productItem.getVersions();

        // Construct SWID tag components
        StringBuilder swidBuilder = new StringBuilder(SWID_PREFIX);
        swidBuilder.append(name.replace(" ", "_")); // Replace spaces with underscores
        for (String version : versions) {
            swidBuilder.append(':').append(version);
        }

        return swidBuilder.toString();
    }

}
