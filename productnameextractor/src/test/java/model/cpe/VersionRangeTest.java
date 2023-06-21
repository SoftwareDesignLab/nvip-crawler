package model.cpe;

import model.cpe.ProductVersion;
import model.cpe.VersionRange;
import org.junit.Test;

import static org.junit.Assert.*;

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
