/**
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
*/

package versionmanager;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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

import model.cpe.ProductVersion;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Class to test VersionManager functionality and methods
 *
 * @author Paul Vickers
 * @author Richard Sawh
 *
 */
public class VersionManagerTest {
    @Test
    public void addExactRangeFromStringTest(){
        final String rangeString = "1.5";

        VersionManager manager = new VersionManager();
        manager.addRangeFromString(rangeString);

        assertEquals(1, manager.getVersionRanges().size());
        assertTrue(manager.getVersionRanges().toString().contains("EXACT 1.5"));
    }

    @Test
    public void addBeforeRangeFromStringTest(){
        final String rangeString = "before 1.5";

        VersionManager manager = new VersionManager();
        manager.addRangeFromString(rangeString);

        assertEquals(1, manager.getVersionRanges().size());
        assertTrue(manager.getVersionRanges().toString().contains("BEFORE 1.5"));
    }

    @Test
    public void addAfterRangeFromStringTest(){
        final String rangeString = "after 1.5";

        VersionManager manager = new VersionManager();
        manager.addRangeFromString(rangeString);

        assertEquals(1, manager.getVersionRanges().size());
        assertTrue(manager.getVersionRanges().toString().contains("AFTER 1.5"));
    }

    @Test
    public void formatVersionsTest(){
        String[] versionWords = new String[10];
        versionWords[0] = "before";
        versionWords[1] = "1.8.2.,";
        versionWords[2] = "v1.9.3";
        versionWords[3] = "prior";
        versionWords[4] = "to";
        versionWords[5] = "1.4.x,";
        versionWords[6] = "(1.4.2a";
        versionWords[7] = "to";
        versionWords[8] = "1.7.5b)";
        versionWords[9] = "3.8.5+";

        VersionManager manager = new VersionManager();
        manager.formatVersionWords(versionWords);

        assertEquals(versionWords[0], "before");
        assertEquals(versionWords[1], "1.8.2");
        assertEquals(versionWords[2], "1.9.3");
        assertEquals(versionWords[3], "prior");
        assertEquals(versionWords[4], "to");
        assertEquals(versionWords[5], "1.4.x");
        assertEquals(versionWords[6], "1.4.2");
        assertEquals(versionWords[7], "to");
        assertEquals(versionWords[8], "1.7.5");
        assertEquals(versionWords[9], "3.8.5+");
    }

    @Test
    public void isVersionFailTest(){
        String version1 = "1.8.4,";
        String version2 = "hello";
        assertFalse(VersionManager.isVersion(version1));
        assertFalse(VersionManager.isVersion(version2));
    }

    @Test
    public void isVersionPassTest(){
        String version1 = "1.9";
        String version2 = "2023";
        assertTrue(VersionManager.isVersion(version1));
        assertTrue(VersionManager.isVersion(version2));
    }

    @Test
    public void processVersionsTest(){
        String[] versionWords = new String[10];
        versionWords[0] = "before";
        versionWords[1] = "1.8.2.,";
        versionWords[2] = "v1.9.3";
        versionWords[3] = "prior";
        versionWords[4] = "to";
        versionWords[5] = "1.4.x,";
        versionWords[6] = "(1.4.2a";
        versionWords[7] = "to";
        versionWords[8] = "1.7.5b)";
        versionWords[9] = "3.8.5+";

        VersionManager manager = new VersionManager();
        manager.processVersions(versionWords);

        assertEquals(6, manager.getVersionRanges().size());
        assertTrue(manager.getVersionRanges().toString().contains("BEFORE 1.8.2"));
        assertTrue(manager.getVersionRanges().toString().contains("EXACT 1.9.3"));
        assertTrue(manager.getVersionRanges().toString().contains("BEFORE 1.4"));
        assertTrue(manager.getVersionRanges().toString().contains("EXACT 1.4.2"));
        assertTrue(manager.getVersionRanges().toString().contains("1.4.2 THROUGH 1.7.5"));
        assertTrue(manager.getVersionRanges().toString().contains("AFTER 3.8.5"));
    }

    @Test
    public void processVersionsEmptyTest(){
        String[] versionWords = new String[10];
        versionWords[0] = "before";
        versionWords[1] = "microsoft";
        versionWords[2] = "v1.9.3jajs32";
        versionWords[3] = "prior";
        versionWords[4] = "to";
        versionWords[5] = "before";
        versionWords[6] = "after";
        versionWords[7] = "not";
        versionWords[8] = "versions8";
        versionWords[9] = "windows";

        VersionManager manager = new VersionManager();
        manager.processVersions(versionWords);

        assertEquals(0, manager.getVersionRanges().size());
    }

    @Test
    public void isAffectedPassTest(){
        String[] versionWords = new String[10];
        versionWords[0] = "before";
        versionWords[1] = "1.8.2.,";
        versionWords[2] = "v1.9.3";
        versionWords[3] = "prior";
        versionWords[4] = "to";
        versionWords[5] = "1.4.x,";
        versionWords[6] = "(1.4.2a";
        versionWords[7] = "to";
        versionWords[8] = "1.7.5b)";
        versionWords[9] = "3.8.5+";

        VersionManager manager = new VersionManager();
        manager.processVersions(versionWords);

        ProductVersion version1 = new ProductVersion("1.5.6");
        ProductVersion version2 = new ProductVersion("4.0");
        ProductVersion version3 = new ProductVersion("1.3.2.67");
        ProductVersion version4 = new ProductVersion("1.9.3");

        assertTrue(manager.isAffected(version1));
        assertTrue(manager.isAffected(version2));
        assertTrue(manager.isAffected(version3));
        assertTrue(manager.isAffected(version4));
    }

    @Test
    public void isAffectedFailTest(){
        String[] versionWords = new String[10];
        versionWords[0] = "before";
        versionWords[1] = "1.8.2.,";
        versionWords[2] = "v1.9.3";
        versionWords[3] = "prior";
        versionWords[4] = "to";
        versionWords[5] = "1.4.x,";
        versionWords[6] = "(1.4.2a";
        versionWords[7] = "to";
        versionWords[8] = "1.7.5b)";
        versionWords[9] = "3.8.5+";

        VersionManager manager = new VersionManager();
        manager.processVersions(versionWords);

        ProductVersion version1 = new ProductVersion("2.7");
        ProductVersion version2 = new ProductVersion("1.9.3.2");
        ProductVersion version3 = new ProductVersion("1.8.4");
        ProductVersion version4 = new ProductVersion("3.8.4");

        assertFalse(manager.isAffected(version1));
        assertFalse(manager.isAffected(version2));
        assertFalse(manager.isAffected(version3));
        assertFalse(manager.isAffected(version4));
    }

    @Test
    public void processVersionsBetweenTest() {
        String[] versionWords = {
                "before", "1.8.2.,", "v1.9.3", "between", "1.4", "and", "1.7.5", "3.8.5+"
        };

        VersionManager manager = new VersionManager();
        manager.processVersions(versionWords);

        assertEquals(5, manager.getVersionRanges().size());
        assertTrue(manager.getVersionRanges().toString().contains("BEFORE 1.8.2"));
        assertTrue(manager.getVersionRanges().toString().contains("EXACT 1.9.3"));
        assertTrue(manager.getVersionRanges().toString().contains("1.4 THROUGH 1.7.5"));
        assertTrue(manager.getVersionRanges().toString().contains("AFTER 3.8.5"));
    }

    @Test
    public void testProcessVersions() {
        VersionManager processor = new VersionManager();

        // Test 1: Standalone version "1.5.6"
        String[] versionWords1 = {"1.5.6"};
        processor.processVersions(versionWords1);
        assertEquals(1, processor.getVersionRanges().size());

        // Test 2: Through case "1.2.5 through 2.4.1"
        String[] versionWords2 = {"1.2.5", "through", "2.4.1"};
        processor.processVersions(versionWords2);
        assertEquals(3, processor.getVersionRanges().size());

        // Test 3: Before case "before 3.7.1"
        String[] versionWords3 = {"before", "3.7.1"};
        processor.processVersions(versionWords3);
        assertEquals(4, processor.getVersionRanges().size());

        // Test 4: After case "after 3.7.1"
        String[] versionWords4 = {"after", "3.7.1"};
        processor.processVersions(versionWords4);
        assertEquals(5, processor.getVersionRanges().size());

        // Test 5: "before" and "after" with "and" case
        String[] versionWords5 = {"1.8", "and", "earlier"};
        processor.processVersions(versionWords5);
        assertEquals(7, processor.getVersionRanges().size());

        // Test 6: "before" and "after" with "and" case
        String[] versionWords6 = {"6.3.1", "and", "prior", "versions"};
        processor.processVersions(versionWords6);
        assertEquals(9, processor.getVersionRanges().size());

        // Test 7: "between" case "between 1.5 and 2.8"
        String[] versionWords7 = {"between", "1.5", "and", "2.8"};
        processor.processVersions(versionWords7);
        assertEquals(11, processor.getVersionRanges().size());

        // Test 8: "3.9+" case
        String[] versionWords8 = {"3.9+"};
        processor.processVersions(versionWords8);
        assertEquals(12, processor.getVersionRanges().size());

        // Test 9: "<1.2.4" case
        String[] versionWords9 = {"<1.2.4"};
        processor.processVersions(versionWords9);
        assertEquals(13, processor.getVersionRanges().size());

        // Test 10: ">1.2.4" case
        String[] versionWords10 = {">1.2.4"};
        processor.processVersions(versionWords10);
        assertEquals(14, processor.getVersionRanges().size());

        // Test 11: Standalone version with ".x" "8.2.x"
        String[] versionWords11 = {"8.2.x"};
        processor.processVersions(versionWords11);
        assertEquals(15, processor.getVersionRanges().size());

        // Test 12: Before case with ".x" "before 5.x"
        String[] versionWords12 = {"before", "5.x"};
        processor.processVersions(versionWords12);
        assertEquals(16, processor.getVersionRanges().size());

        // Test 13: After case with ".x" "after 5.x"
        String[] versionWords13 = {"after", "5.x"};
        processor.processVersions(versionWords13);
        assertEquals(17, processor.getVersionRanges().size());

        // Test 14: Through case with ".x" "4.2.3 through 5.x"
        String[] versionWords14 = {"4.2.3", "through", "5.x"};
        processor.processVersions(versionWords14);
        assertEquals(19, processor.getVersionRanges().size());

        // Test 15: Standalone ".x" version "5.x"
        String[] versionWords15 = {"5.x"};
        processor.processVersions(versionWords15);
        assertEquals(20, processor.getVersionRanges().size());
    }

}
