package model.cpe;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for VersionRange class
 *
 * @author Dylan Mulligan
 */
public class VersionRangeTest {
    @Test
    public void basicExactVersionRangeTest(){
        final VersionRange versionRange = new VersionRange("1.2.3");

        assertEquals(VersionRange.RangeType.EXACT, versionRange.getType());
        assertEquals(new ProductVersion("1.2.3"), versionRange.getVersion1());

        assertTrue(versionRange.withinRange(new ProductVersion("1.2.3")));
        assertFalse(versionRange.withinRange(new ProductVersion("1.2.2")));
        assertFalse(versionRange.withinRange(new ProductVersion("1.2.4")));
    }

    @Test
    public void basicBeforeVersionRangeTest(){
        final VersionRange versionRange = new VersionRange("before 1.2.3");

        assertEquals(VersionRange.RangeType.BEFORE, versionRange.getType());
        assertEquals(new ProductVersion("1.2.3"), versionRange.getVersion1());

        assertTrue(versionRange.withinRange(new ProductVersion("1.2.3")));
        assertTrue(versionRange.withinRange(new ProductVersion("1.2.2")));
        assertFalse(versionRange.withinRange(new ProductVersion("1.2.4")));
    }

    @Test
    public void basicAfterVersionRangeTest(){
        final VersionRange versionRange = new VersionRange("after 1.2.3");

        assertEquals(VersionRange.RangeType.AFTER, versionRange.getType());
        assertEquals(new ProductVersion("1.2.3"), versionRange.getVersion1());

        assertTrue(versionRange.withinRange(new ProductVersion("1.2.3")));
        assertFalse(versionRange.withinRange(new ProductVersion("1.2.2")));
        assertTrue(versionRange.withinRange(new ProductVersion("1.2.4")));
    }

    @Test
    public void basicThroughVersionRangeTest(){
        final VersionRange versionRange = new VersionRange("1.0.12 through 1.2.3");

        assertEquals(VersionRange.RangeType.THROUGH, versionRange.getType());
        assertEquals(new ProductVersion("1.0.12"), versionRange.getVersion1());
        assertEquals(new ProductVersion("1.2.3"), versionRange.getVersion2());

        assertTrue(versionRange.withinRange(new ProductVersion("1.0.12")));
        assertTrue(versionRange.withinRange(new ProductVersion("1.2.3")));
        assertTrue(versionRange.withinRange(new ProductVersion("1.0.17")));
        assertFalse(versionRange.withinRange(new ProductVersion("1.0.0")));
        assertFalse(versionRange.withinRange(new ProductVersion("1.2.4")));
    }
}
