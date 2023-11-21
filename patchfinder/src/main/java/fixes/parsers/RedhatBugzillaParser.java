package fixes.parsers;

import fixes.Fix;

import java.util.HashSet;
import java.util.Set;

public class RedhatBugzillaParser extends RedhatParser {
    protected RedhatBugzillaParser(String cveId, String url){
        super(cveId, url);
    }


    @Override
    protected Set<Fix> parseWebPage() {
        Set<Fix> newFixes = new HashSet<>();

        // TODO: Add Bugzilla specific implementation
        String resolution = this.DOM.select("section[class=field_kcs_resolution_txt]").select("p").text();

        newFixes.add(new Fix(cveId, resolution, url));
        return newFixes;
    }
}
