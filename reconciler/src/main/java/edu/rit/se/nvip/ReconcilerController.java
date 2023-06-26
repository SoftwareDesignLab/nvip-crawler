package edu.rit.se.nvip;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.filter.Filter;
import edu.rit.se.nvip.filter.FilterFactory;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.model.VulnSetWrapper;
import edu.rit.se.nvip.process.Processor;
import edu.rit.se.nvip.process.ProcessorFactory;
import edu.rit.se.nvip.reconciler.Reconciler;
import edu.rit.se.nvip.reconciler.ReconcilerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.stream.Collectors;

public class ReconcilerController {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private final DatabaseHelper dbh;
    private final Reconciler reconciler;
    private final List<Filter> filters = new ArrayList<>();
    private final List<Processor> processors = new ArrayList<>();

    private static final Map<String, Object> characterizationVars = new HashMap<>();

    public ReconcilerController(List<String> filterTypes, String reconcilerType, List<String> processorTypes, Map<String, Integer> knownCveSources) {
        this.dbh = DatabaseHelper.getInstance();
        addLocalFilters();
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
        Set<CompositeVulnerability> reconciledVulns = new HashSet<>();
        for (String job : jobs) {
            CompositeVulnerability vuln = handleReconcilerJob(job);
            if (vuln != null) {
                reconciledVulns.add(vuln);
            }
        }

        runProcessors(reconciledVulns);

        characterizeCVEs(reconciledVulns);

        int upsertCount = 0;
        for (CompositeVulnerability vuln : reconciledVulns) {
            int status = dbh.insertOrUpdateVulnerabilityFull(vuln);
            if (status != -1) {
                upsertCount += status;
            }
            logger.info("Finished job for cveId " + vuln.getCveId());
        }
        logger.info("Upserted {} vulnerabilities", upsertCount);
    }

    private List<CompositeVulnerability> characterizeCVEs(Set<CompositeVulnerability> crawledVulnerabilityList) {

        // characterize
        logger.info("Characterizing and scoring NEW CVEs...");

        try {
            String[] trainingDataInfo = {"characterization/", "AttackTheater.csv,Context.csv,ImpactMethod.csv,LogicalImpact.csv,Mitigation.csv"};
            logger.info("Setting NVIP_CVE_CHARACTERIZATION_LIMIT to {}", System.getenv("NVIP_CVE_CHARACTERIZATION_LIMIT"));

            CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], "ML",
                    "Vote");

            List<CompositeVulnerability> cveList = new ArrayList<>(crawledVulnerabilityList);

            return cveCharacterizer.characterizeCveList(cveList,
                   Integer.parseInt(System.getenv("NVIP_CVE_CHARACTERIZATION_LIMIT")));
        }
        catch (NullPointerException | NumberFormatException e) { logger.warn("Could not fetch NVIP_CVE_CHARACTERIZATION_TRAINING_DATA or NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR from env vars, defaulting to {}", System.getenv("NVIP_CVE_CHARACTERIZATION_LIMIT")); }


        return null;
    }

    private CompositeVulnerability handleReconcilerJob(String cveId) {
        // pull data
        Set<RawVulnerability> rawVulns = dbh.getRawVulnerabilities(cveId);
        int rawCount = rawVulns.size();
        VulnSetWrapper wrapper = new VulnSetWrapper(rawVulns);
        // mark new vulns as unevaluated
        int newRawCount = wrapper.setNewToUneval();
        // get an existing vuln from prior reconciliation if one exists
        CompositeVulnerability existing = dbh.getCompositeVulnerability(cveId);
        // filter in waves by priority
        FilterReturn firstWaveReturn = runFilters(wrapper.firstFilterWave()); //high prio sources
        FilterReturn secondWaveReturn = runFilters(wrapper.secondFilterWave()); //either empty or low prio depending on filter status of high prio sources
        // update the filter status in the db for new and newly evaluated vulns
        dbh.updateFilterStatus(wrapper.toUpdate());
        logger.info("{} raw vulnerabilities with CVE ID {} were found and {} were new.\n" +
                        "The first wave of filtering passed {} out of {} new high priority sources.\n" +
                        "The second wave of filtering passed {} out of {} new backup low priority sources.\n" +
                        "In total, {} distinct descriptions were explicitly filtered.",
                rawCount, cveId, newRawCount,
                firstWaveReturn.numPassed, firstWaveReturn.numIn,
                secondWaveReturn.numPassed, secondWaveReturn.numIn,
                firstWaveReturn.numDistinct + secondWaveReturn.numDistinct);
        // reconcile
        CompositeVulnerability out = reconciler.reconcile(existing, wrapper.toReconcile());
        // link all the rawvulns to the compvuln, regardless of filter/reconciliation status
        // we do this because publish dates and mod dates should be determined by all sources, not just those with good descriptions
        out.setPotentialSources(rawVulns);
        return out;
    }


    private FilterReturn runFilters(Set<RawVulnerability> vulns) {
        // set up equivalence classes partitioned by equal descriptions
        Map<String, Set<RawVulnerability>> equivClasses = new HashMap<>();
        Set<RawVulnerability> samples = new HashSet<>(); // holds one from each equivalence class
        for (RawVulnerability rawVuln : vulns) {
            String desc = rawVuln.getDescription();
            if (!equivClasses.containsKey(desc)) {
                equivClasses.put(desc, new HashSet<>());
                samples.add(rawVuln);
            }
            equivClasses.get(desc).add(rawVuln);
        }
        for (Filter filter : filters) {
            filter.filterAll(samples);
        }
        // update filter statuses in each equiv class to match its sample
        for (RawVulnerability sample : samples) {
            for (RawVulnerability rv : equivClasses.get(sample.getDescription())) {
                rv.setFilterStatus(sample.getFilterStatus());
            }
        }
        int numPassed = vulns.stream().filter(v->v.getFilterStatus() == RawVulnerability.FilterStatus.PASSED).collect(Collectors.toSet()).size();
        return new FilterReturn(vulns.size(), samples.size(), numPassed);
    }

    private static class FilterReturn {
        public int numIn;
        public int numDistinct;
        public int numPassed;
        public FilterReturn(int numIn, int numDistinct, int numPassed) {
            this.numIn = numIn;
            this.numDistinct = numDistinct;
            this.numPassed = numPassed;
        }
    }

    private void runProcessors(Set<CompositeVulnerability> vulns) {
        for (Processor ap : processors) {
            ap.process(vulns);
        }
    }

    /**
     * Helper method for adding all local/simple filters
     */
    private void addLocalFilters() {
        filters.add(FilterFactory.createFilter(FilterFactory.BLANK_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.CVE_MATCHES_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.INTEGER_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.MULTIPLE_CVE_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.DESCRIPTION_SIZE));
    }
}
