package edu.rit.se.nvip;

import edu.rit.se.nvip.filter.Filter;
import edu.rit.se.nvip.filter.FilterFactory;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.process.Processor;
import edu.rit.se.nvip.process.ProcessorFactory;
import edu.rit.se.nvip.reconciler.Reconciler;
import edu.rit.se.nvip.reconciler.ReconcilerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

public class ReconcilerController {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private final DatabaseHelper dbh;
    private final Reconciler reconciler;
    private final List<Filter> filters = new ArrayList<>();
    private final List<Processor> processors = new ArrayList<>();

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

    /**
     * Helper method for adding all local/simple filters
     */
    private void addLocalFilters() {
        filters.add(FilterFactory.createFilter(FilterFactory.BLANK_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.CVE_MATCHES_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.INTEGER_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.MULTIPLE_CVE_DESCRIPTION));
    }
}
