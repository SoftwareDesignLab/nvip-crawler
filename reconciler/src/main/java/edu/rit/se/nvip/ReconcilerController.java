package edu.rit.se.nvip;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.filter.FilterHandler;
import edu.rit.se.nvip.filter.FilterReturn;
import edu.rit.se.nvip.messager.Messager;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.model.VulnSetWrapper;
import edu.rit.se.nvip.process.Processor;
import edu.rit.se.nvip.process.ProcessorFactory;
import edu.rit.se.nvip.reconciler.Reconciler;
import edu.rit.se.nvip.reconciler.ReconcilerFactory;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;

public class ReconcilerController {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private final DatabaseHelper dbh;
    private final Reconciler reconciler;
    private final FilterHandler filterHandler;
    private final List<Processor> processors = new ArrayList<>();
    private final Messager messager = new Messager();

    public ReconcilerController() {
        this.dbh = DatabaseHelper.getInstance();
        filterHandler = new FilterHandler(ReconcilerEnvVars.getFilterList());
        this.reconciler = ReconcilerFactory.createReconciler(ReconcilerEnvVars.getReconcilerType());
        this.reconciler.setKnownCveSources(ReconcilerEnvVars.getKnownSourceMap());
        for (String processorType : ReconcilerEnvVars.getProcessorList()) {
            processors.add(ProcessorFactory.createProcessor(processorType));
        }
    }

    public void main(Set<String> jobs) {
        logger.info(jobs.size() + " jobs found for reconciliation");
        Set<CompositeVulnerability> reconciledVulns = new HashSet<>();
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        List<Future<CompositeVulnerability>> futures = new ArrayList<>();
        for (String job : jobs) {
            ReconcileTask task = new ReconcileTask(job);
            Future<CompositeVulnerability> future = executor.submit(task);
            futures.add(future);
        }
        for (Future<CompositeVulnerability> futureVuln : futures) {
            try {
                CompositeVulnerability compVuln = futureVuln.get();
                if (compVuln != null){
                    reconciledVulns.add(compVuln);
                }
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException(e);
            }
        }
        messager.sendPNEFinishMessage();

        runProcessors(reconciledVulns);

        characterizeCVEs(reconciledVulns);

        for (CompositeVulnerability vuln : reconciledVulns){
            dbh.updateCVSS(vuln);
            dbh.updateVDO(vuln);
        }


    }

    private class ReconcileTask implements Callable<CompositeVulnerability> {
        private final String job;
        public ReconcileTask(String job) {
            this.job = job;
        }

        @Override
        public CompositeVulnerability call() throws Exception {
            return handleReconcilerJob(job);
        }
    }

    private List<CompositeVulnerability> characterizeCVEs(Set<CompositeVulnerability> crawledVulnerabilityList) {
        // characterize
        logger.info("Characterizing and scoring NEW CVEs...");

        try {
            String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
            logger.info("Setting NVIP_CVE_CHARACTERIZATION_LIMIT to {}", ReconcilerEnvVars.getCharacterizationLimit());

            CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], "ML",
                    "Vote");

            List<CompositeVulnerability> cveList = new ArrayList<>(crawledVulnerabilityList);

            return cveCharacterizer.characterizeCveList(cveList,
                   ReconcilerEnvVars.getCharacterizationLimit());
        }
        catch (NullPointerException | NumberFormatException e) {
            logger.warn("Could not fetch NVIP_CVE_CHARACTERIZATION_TRAINING_DATA or NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR from env vars");
        }


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
        FilterReturn firstWaveReturn = filterHandler.runFilters(wrapper.firstFilterWave()); //high prio sources
        FilterReturn secondWaveReturn = filterHandler.runFilters(wrapper.secondFilterWave()); //either empty or low prio depending on filter status of high prio sources
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
        if(out == null){
            return null;
        }
        out.setPotentialSources(rawVulns);

        dbh.insertOrUpdateVulnerabilityFull(out);

        logger.info("Finished job for cveId " + out.getCveId());


        List<String> outList = new ArrayList<>();
        if (out.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.NEW || out.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.UPDATED){
            outList.add(out.getCveId());
            messager.sendPNEMessage(outList);
        }

        return out;
    }

    private void runProcessors(Set<CompositeVulnerability> vulns) {
        for (Processor ap : processors) {
            ap.process(vulns);
        }
    }
}
