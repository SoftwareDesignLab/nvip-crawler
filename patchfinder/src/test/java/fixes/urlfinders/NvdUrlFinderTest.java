package fixes.urlfinders;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class NvdUrlFinderTest extends FixUrlFinderTest<NvdUrlFinder> {
    public NvdUrlFinderTest() {
        super(new NvdUrlFinder());
    }

    @Override
    public void testRun() {
        // TODO: Test parseWebpage with second cve/url

    }
}
