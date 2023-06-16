package model.cpe;

import model.cpe.ProductVersion;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Class to test ProductVersion Implementation
 *
 * @author Dylan Mulligan
 *
 */
public class ProductVersionTest {
    @Test
    public void basicVersionTest(){
        final String versionString = "1.2.3";

        final ProductVersion version = new ProductVersion(versionString);

        assertEquals(versionString, version.toString());
    }

    @Test
    public void complexVersionTest(){
        final String versionString = "12.2.31.4";

        final ProductVersion version = new ProductVersion(versionString);

        assertEquals(versionString, version.toString());
    }

    @Test
    public void invalidVersionTest2(){
        final String versionString = "-";

        try {
            new ProductVersion(versionString);
            fail(String.format("Version %s should have thrown an error and did not", versionString));
        } catch (IllegalArgumentException ignored) { }
    }

    @Test
    public void invalidVersionTest3(){
        final String versionString = "version";

        try {
            new ProductVersion(versionString);
            fail(String.format("Version %s should have thrown an error and did not", versionString));
        } catch (IllegalArgumentException ignored) { }
    }
}
