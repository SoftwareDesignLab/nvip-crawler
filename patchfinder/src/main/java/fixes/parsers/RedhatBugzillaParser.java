package fixes.parsers;

import fixes.Fix;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class RedhatBugzillaParser extends RedhatParser {
    protected RedhatBugzillaParser(String cveId, String url){
        super(cveId, url);
    }


    @Override
    protected List<Fix> parseWebPage() throws IOException {
        List<Fix> newFixes = new ArrayList<>();

        // TODO: Add Bugzilla specific implementation
        String resolution = this.DOM.select("section[class=field_kcs_resolution_txt]").select("p").text();

        newFixes.add(new Fix(cveId, resolution, url));
        return newFixes;
    }
}
