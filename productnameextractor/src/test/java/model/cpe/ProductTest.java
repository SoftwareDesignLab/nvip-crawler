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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for Product class
 *
 * @author Richard Sawh
 */
public class ProductTest {

    @Test
    public void testGetVersion_WithValidVersion() {
        // Create a Product object with a domain containing a valid version
        Product product = new Product("domain-1.0", "cpe", 1);

        // Assert that the version is extracted correctly
        Assertions.assertEquals("1.0", product.getVersion());
    }

    @Test
    public void testGetVersion_WithInvalidVersion() {
        // Create a Product object with a domain that does not contain a valid version
        Product product = new Product("domain", "cpe", 1);

        // Assert that an empty string is returned for the version
        Assertions.assertEquals("", product.getVersion());
    }

    @Test
    public void testEquals_WithEqualObjects() {
        // Create two Product objects with the same CPE
        Product product1 = new Product("domain1", "cpe", 1);
        Product product2 = new Product("domain2", "cpe", 2);

        // Assert that the two objects are equal
        Assertions.assertEquals(product1, product2);
    }

    @Test
    public void testEquals_WithDifferentObjects() {
        // Create two Product objects with different CPEs
        Product product1 = new Product("domain", "cpe1", 1);
        Product product2 = new Product("domain", "cpe2", 2);

        // Assert that the two objects are not equal
        Assertions.assertNotEquals(product1, product2);
    }

    @Test
    public void testHashCode() {
        // Create a Product object
        Product product = new Product("domain", "cpe", 1);

        // Assert the hash code of the object
        Assertions.assertEquals("cpe".hashCode(), product.hashCode());
    }

    @Test
    public void testToString() {
        // Create a Product object
        Product product = new Product("domain", "cpe", 1);

        // Assert the string representation of the object
        Assertions.assertEquals("domain", product.toString());
    }
}
