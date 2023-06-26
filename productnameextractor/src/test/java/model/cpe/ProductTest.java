package model.cpe;

import edu.rit.se.nvip.model.cpe.Product;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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
