package fixes.urlfinders;

import fixes.Fix;
import fixes.FixFinder;
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class CXSecurityUrlFinderTest extends  FixUrlFinderTest<CXSecurityUrlFinder>{

    public CXSecurityUrlFinderTest() {
        super(new CXSecurityUrlFinder());
    }
    static {FixFinder.init();}
    //zero urls  are found
    @Override
    public void testRun() {
        // TODO: Test parseWebpage with second cve/url
        String cveId ="CVE-2023-3990";


        List<String> actual =  this.fixUrlFinder.run(cveId);
        List<String> expected = List.of("https://cxsecurity.com/cvemap", "https://cxsecurity.com/cveshow/CVE-2023-3990", "https://cxsecurity.com/cveshow/CVE-2023-3990","https://cxsecurity.com/cveshow/CVE-2023-3990");


        assertEquals(expected, actual);
    }



}
