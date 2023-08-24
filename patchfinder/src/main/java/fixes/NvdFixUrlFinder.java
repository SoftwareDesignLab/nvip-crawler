package fixes;

import java.io.IOException;
import java.util.ArrayList;

public class NvdFixUrlFinder extends FixUrlFinder {

    public NvdFixUrlFinder() { }

    @Override
    protected ArrayList<String> run(String cveId) throws IOException {
        logger.info("Getting fixes for CVE: {}", cveId);
        ArrayList<String> urlList = new ArrayList<>();

        // Get all sources for the cve
        ArrayList<String> sources = FixFinder.getDatabaseHelper().getCveSourcesNVD(cveId);

        // Test each source for a valid connection
        for (String source : sources) {
            if (testConnection(source)) {
                urlList.add(source);
            }
        }
        return urlList;
    }
}