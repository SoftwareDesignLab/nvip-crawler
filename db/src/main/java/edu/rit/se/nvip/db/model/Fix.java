/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

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
        // Use the full description unless too long
        String shortFixDescription = fixDescription;
        // Shorten description to 30 chars (and ...) if too long
        if(shortFixDescription.length() > 30) shortFixDescription = shortFixDescription.substring(0, 30) + "...";

        return String.format("Fix [cve_id=%s, fix_description=%s, source_url=%s]",
                cveId,
                shortFixDescription,
                sourceUrl
        );
    }
}
