package fixes;

import db.DatabaseHelper;

import java.io.IOException;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NvdFixUrlFinder extends FixUrlFinder {

    private static DatabaseHelper databaseHelper;
    private static final Logger logger = LogManager.getLogger(VulnerabilityFixUrlFinder.class.getName());

    public NvdFixUrlFinder(DatabaseHelper databaseHelper) {
        NvdFixUrlFinder.databaseHelper = databaseHelper;
    }


    @Override
    protected ArrayList<String> run(String cveId) throws IOException {
        logger.info("Getting fixes for CVE: {}", cveId);
        ArrayList<String> urlList = new ArrayList<>();

        //get all sources for the cve
        ArrayList<String> sources = databaseHelper.getCveSourcesNVD(cveId);

        //test each source for a valid connection
        for (String source : sources) {
            if (testConnection(source)) {
                urlList.add(source);
            }
        }
        return urlList;
    }
}