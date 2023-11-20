package edu.rit.se.nvip.db.model;

/**
 * Model class for fixes found by FixFinder
 *
 * @author Dylan Mulligan
 * @author Richard Sawh
 * @author Paul Vickers
 */
public class Fix {
    private final String cveId;
    private final String fixDescription;
    private final String sourceUrl;

    /**
     * Model class for fix objects
     *
     * @param cveId         the ID of the cve
     * @param fixDescription the description of the fix
     * @param sourceUrl    the source URL
     */
    public Fix(String cveId, String fixDescription, String sourceUrl) {
        // Validate arguments
        if(cveId == null || cveId.length() == 0)
            throw new IllegalArgumentException("Illegal value for cveId, ensure it is not null or an empty string");
        if(sourceUrl == null || sourceUrl.length() == 0)
            throw new IllegalArgumentException("Illegal value for sourceUrl, ensure it is not null or an empty string");

        // Set values
        this.cveId = cveId;
        this.fixDescription = fixDescription;
        this.sourceUrl = sourceUrl;
    }

    // Getters

    public String getCveId() { return this.cveId; }
    public String getFixDescription() { return this.fixDescription; }
    public String getSourceUrl() { return this.sourceUrl; }

    /**
     * @return the fix as a string
     */
    public String toString() {
        return String.format("Fix [cve_id=%s, fix_description=%s, source_url=%s]",
                cveId,
                fixDescription,
                sourceUrl
        );
    }
}
