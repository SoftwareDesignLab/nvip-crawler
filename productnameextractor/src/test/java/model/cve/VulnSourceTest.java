package model.cve;

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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class VulnSourceTest {

    @Test
    public void testEquals_WithEqualObjects() {
        // Create two VulnSource objects with the same URL
        VulnSource source1 = new VulnSource("CVE-2023-1234", "https://example.com/source");
        VulnSource source2 = new VulnSource("CVE-2023-5678", "https://example.com/source");

        // Assert that the two objects are equal
        Assertions.assertEquals(source1, source2);
    }

    @Test
    public void testEquals_WithDifferentObjects() {
        // Create two VulnSource objects with different URLs
        VulnSource source1 = new VulnSource("CVE-2023-1234", "https://example.com/source1");
        VulnSource source2 = new VulnSource("CVE-2023-5678", "https://example.com/source2");

        // Assert that the two objects are not equal
        Assertions.assertNotEquals(source1, source2);
    }

    @Test
    public void testEquals_WithNullObject() {
        // Create a VulnSource object
        VulnSource source = new VulnSource("CVE-2023-1234", "https://example.com/source");

        // Assert that the object is not equal to null
        Assertions.assertNotEquals(source, null);
    }

    @Test
    public void testHashCode_WithNullURL() {
        // Create a VulnSource object with a null URL
        VulnSource source = new VulnSource("CVE-2023-1234", null);

        // Assert that the hash code is 0
        Assertions.assertEquals(0, source.hashCode());
    }

    @Test
    public void testHashCode_WithNonNullURL() {
        // Create a VulnSource object with a non-null URL
        VulnSource source = new VulnSource("CVE-2023-1234", "https://example.com/source");

        // Assert that the hash code is as expected
        Assertions.assertEquals("https://example.com/source".hashCode(), source.hashCode());
    }
}