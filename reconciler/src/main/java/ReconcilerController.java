import characterizer.CveCharacterizer;
import db.DatabaseHelper;
import model.CompositeVulnerability;
import filter.Filter;
import filter.FilterFactory;
import model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import process.Processor;
import process.ProcessorFactory;
import reconciler.Reconciler;
import reconciler.ReconcilerFactory;

import java.util.*;

public class ReconcilerController {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private final DatabaseHelper dbh;
    private final Reconciler reconciler;
    private final List<Filter> filters = new ArrayList<>();
    private final List<Processor> processors = new ArrayList<>();

    private static final Map<String, Object> characterizationVars = new HashMap<>();

    public ReconcilerController(List<String> filterTypes, String reconcilerType, List<String> processorTypes, Map<String, Integer> knownCveSources) {
        this.dbh = DatabaseHelper.getInstance();
        for (String filterType : filterTypes) {
            filters.add(FilterFactory.createFilter(filterType));
        }
        this.reconciler = ReconcilerFactory.createReconciler(reconcilerType);
        this.reconciler.setKnownCveSources(knownCveSources);
        for (String processorType : processorTypes) {
            processors.add(ProcessorFactory.createProcessor(processorType));
        }
    }

    public void main() {
        Set<String> jobs = dbh.getJobs();
        logger.info(jobs.size() + " jobs found for reconciliation");
        Set<model.CompositeVulnerability> reconciledVulns = new HashSet<>();
        for (String job : jobs) {
            model.CompositeVulnerability vuln = handleReconcilerJob(job);
            if (vuln != null) {
                reconciledVulns.add(vuln);
            }
        }

        runProcessors(reconciledVulns);

        characterizeCVEs(reconciledVulns);

        int upsertCount = 0;
        for (model.CompositeVulnerability vuln : reconciledVulns) {
            int status = dbh.insertOrUpdateVulnerabilityFull(vuln);
            if (status != -1) {
                upsertCount += status;
            }
            logger.info("Finished job for cveId " + vuln.getCveId());
        }
        logger.info("Upserted {} vulnerabilities", upsertCount);
    }

    private List<CompositeVulnerability> characterizeCVEs(Set<CompositeVulnerability> crawledVulnerabilityList) {
        // Parse CAPECs page to link CVEs to a given Attack Pattern in characterizer
        // CapecParser capecParser = new CapecParser();
        // ArrayList<Capec> capecs = capecParser.parseWebPage(crawler);

        // characterize
        logger.info("Characterizing and scoring NEW CVEs...");

        try {
            String[] trainingDataInfo = System.getenv("NVIP_CVE_CHARACTERIZATION_TRAINING_DATA").split(",");
            logger.info("Setting NVIP_CVE_CHARACTERIZATION_LIMIT to {}", System.getenv("NVIP_CVE_CHARACTERIZATION_LIMIT"));
            try{

                CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], System.getenv("NVIP_CHARACTERIZATION_APPROACH"),
                        System.getenv("NVIP_CHARACTERIZATION_METHOD"), false);

                return cveCharacterizer.characterizeCveList((List<CompositeVulnerability>)crawledVulnerabilityList, dbh,
                        (Integer) characterizationVars.get("cveCharacterizationLimit"));
            }catch (NullPointerException | NumberFormatException e) { logger.warn("Could not fetch _________________ from env vars, defaulting to {}", System.getenv("NVIP_CVE_CHARACTERIZATION_LIMIT")); }

        }
        catch (NullPointerException | NumberFormatException e) { logger.warn("Could not fetch NVIP_CVE_CHARACTERIZATION_TRAINING_DATA from env vars, defaulting to {}", System.getenv("NVIP_CVE_CHARACTERIZATION_LIMIT")); }


        // OLD CODE

//        String[] trainingDataInfo = properties.getCveCharacterizationTrainingDataInfo();
//        CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], properties.getCveCharacterizationApproach(),
//                properties.getCveCharacterizationMethod(), false);
//
//        return cveCharacterizer.characterizeCveList(crawledVulnerabilityList, databaseHelper,
//                (Integer) characterizationVars.get("cveCharacterizationLimit"));
        return null;
    }

    private CompositeVulnerability handleReconcilerJob(String cveId) {
        // pull data
        int rawCount;
        int newRawCount;
        int rejectCount;
        Set<RawVulnerability> rawVulns = dbh.getRawVulnerabilities(cveId);
        rawCount = rawVulns.size();
        newRawCount = rawCount;
        CompositeVulnerability existing = dbh.getCompositeVulnerability(cveId);
        if (existing != null) {
            // isolate new raw vulnerabilities
            newRawCount -= removeUsedVulns(rawVulns, existing.getComponents());
        }
        // filter
        Set<RawVulnerability> failed = runFilters(rawVulns);
        rejectCount = failed.size();
        dbh.markGarbage(failed);
        logger.info("{} raw vulnerabilities with CVE ID {} were found, {} were new, {} of the new raw vulns were rejected, and {} are being submitted for reconciliation",
                rawCount, cveId, newRawCount, rejectCount, newRawCount);
        // reconcile
        return reconciler.reconcile(existing, rawVulns);
    }

    private Set<RawVulnerability> runFilters(Set<RawVulnerability> vulns) {
        Set<RawVulnerability> out = new HashSet<>();
        for (Filter filter : filters) {
            out.addAll(filter.filterAll(vulns));
        }
        return out;
    }

    private void runProcessors(Set<CompositeVulnerability> vulns) {
        for (Processor ap : processors) {
            ap.process(vulns);
        }
    }

    private int removeUsedVulns(Set<RawVulnerability> totalList, Set<RawVulnerability> usedList) {
        Iterator<RawVulnerability> iterator = totalList.iterator();
        int count = 0;
        while (iterator.hasNext()) {
            RawVulnerability sample = iterator.next();
            for (RawVulnerability used : usedList) {
                if (sample.equals(used)) {
                    iterator.remove();
                    count++;
                    break;
                }
            }
        }
        return count;
    }
}
