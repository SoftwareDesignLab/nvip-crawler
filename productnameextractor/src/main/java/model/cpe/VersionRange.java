package model.cpe;
/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
                    ProductVersion newVersion1 = new ProductVersion(versionData[0]);
                    ProductVersion newVersion2 = new ProductVersion(versionData[2]);

                    //make sure that "2 through 1.2" becomes "1.2 through 2"
                    if(newVersion1.compareTo(newVersion2) >= 0){
                        this.version1 = newVersion2;
                        this.version2 = newVersion1;
                    }else{
                        this.version1 = new ProductVersion(versionData[0]);
                        this.version2 = new ProductVersion(versionData[2]);
                    }
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
