package edu.rit.se.nvip;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.reconciler.filter.FilterHandler;
import edu.rit.se.nvip.reconciler.filter.FilterReturn;
import edu.rit.se.nvip.mitre.MitreCveController;
import edu.rit.se.nvip.model.*;
import edu.rit.se.nvip.nvd.NvdCveController;
import edu.rit.se.nvip.reconciler.Reconciler;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class ReconcilerController {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private DatabaseHelper dbh;
    private Reconciler reconciler;
    private FilterHandler filterHandler;
    private CveCharacterizer cveCharacterizer;
    private NvdCveController nvdController;
    private MitreCveController mitreController;

    public ReconcilerController(DatabaseHelper dbh, FilterHandler filterHandler, Reconciler reconciler, NvdCveController nvdController, MitreCveController mitreController) {
        this.dbh = dbh;
        this.filterHandler = filterHandler;
        this.reconciler = reconciler;
        this.nvdController = nvdController;
        this.mitreController = mitreController;
    }

    public Set<CompositeVulnerability> reconcileCves(Set<String> cveIds){
        logger.info(cveIds.size() + " jobs found for reconciliation");
        Set<CompositeVulnerability> reconciledVulns = new HashSet<>();

        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        //set up reconcile job tasks, map from cve id to future
        Map<String, Future<CompositeVulnerability>> futures = new HashMap<>();
        for (String cveId : cveIds) {
            ReconcileTask task = new ReconcileTask(cveId);
            Future<CompositeVulnerability> future = executor.submit(task);
            futures.put(cveId, future);
        }
        executor.shutdown();
        //waits for reconcile jobs
        for (String job : futures.keySet()) {
            try {
                CompositeVulnerability compVuln = futures.get(job).get();
                if (compVuln != null){
                    reconciledVulns.add(compVuln);
                }
            } catch (InterruptedException | ExecutionException e) {
                logger.error("Error encountered while reconciling {}", job);
            }
        }
        logger.info("Finished reconciliation stage - sending message to PNE");

        return reconciledVulns;
    }

    public Set<CompositeVulnerability> characterizeCves(Set<CompositeVulnerability> reconciledCves){
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        //characterizer initialization
        CharacterizeTask cTask = new CharacterizeTask();
        Future<CveCharacterizer> futureCharacterizer = executor.submit(cTask);

        logger.info("Starting characterization");
        //run characterizer
        if (ReconcilerEnvVars.getDoCharacterization()) {
            //wait for characterizer task to complete
            try {
                if(cveCharacterizer == null) {
                    cveCharacterizer = futureCharacterizer.get();
                    cveCharacterizer.setSSVCApiBaseUrl(ReconcilerEnvVars.getSSVCApiBaseUrl());
                    cveCharacterizer.setSSVCApiPort(ReconcilerEnvVars.getSSVCApiPort());
                    cveCharacterizer.setSSVCApiUri(ReconcilerEnvVars.getSSVCApiUri());
                }
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException(e);
            }
            characterizeCVEs(reconciledCves);
            Set<CompositeVulnerability> recharacterized = reconciledCves.stream()
                    .filter(CompositeVulnerability::isRecharacterized).collect(Collectors.toSet());

            dbh.insertCvssBatch(recharacterized);
            dbh.insertVdoBatch(recharacterized);
            dbh.insertSSVCSet(recharacterized);
        }
        // PNE team no longer wants a finish message
        //messenger.sendPNEFinishMessage();
        return reconciledCves;
    }

    public void createRunStats(Set<CompositeVulnerability> reconciledCves) {
        logger.info("Updating runstats");
        dbh.insertRun(new RunStats(reconciledCves));
    }

    public void updateTimeGaps(Set<CompositeVulnerability> reconciledCves) {
        logger.info("Starting NVD/MITRE comparisons");
        updateNvdMitre(); // todo this could be done from the start asynchronously, but attaching shouldn't happen until it's done
        Set<CompositeVulnerability> inNvdOrMitre = attachNvdMitre(reconciledCves.stream()
                .filter(v -> v.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.NEW)
                .collect(Collectors.toSet()));
        dbh.insertTimeGapsForNewVulns(inNvdOrMitre);
    }

    private class ReconcileTask implements Callable<CompositeVulnerability> {
        private final String job;
        public ReconcileTask(String job) {
            this.job = job;
        }

        @Override
        public CompositeVulnerability call() {
            try {
                return handleReconcilerJob(job);
            } catch (Exception ex) {
                logger.error("Eror encountered while reconciling {}", job);
                logger.error(ex);
                return null;
            }
        }
    }
    private class CharacterizeTask implements Callable<CveCharacterizer> {

        @Override
        public CveCharacterizer call() {
            if (!ReconcilerEnvVars.getDoCharacterization()) {
                return null; // if we're not going to characterize don't load up the models
            }
           try {
                String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
                logger.info("Setting NVIP_CVE_CHARACTERIZATION_LIMIT to {}", ReconcilerEnvVars.getCharacterizationLimit());
                return new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], ReconcilerEnvVars.getCharacterizationApproach(), ReconcilerEnvVars.getCharacterizationMethod(), dbh);
           } catch (NullPointerException | NumberFormatException e) {
                logger.warn("Could not fetch NVIP_CVE_CHARACTERIZATION_TRAINING_DATA or NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR from env vars");
                return null;
           }
        }
    }

    private void characterizeCVEs(Set<CompositeVulnerability> crawledVulnerabilitySet) {
        logger.info("Characterizing and scoring NEW CVEs...");
        cveCharacterizer.characterizeCveList(crawledVulnerabilitySet, ReconcilerEnvVars.getCharacterizationLimit());
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

        if (out == null){
            return null;
        }

        // link all the rawvulns to the compvuln, regardless of filter/reconciliation status
        // we do this because publish dates and mod dates should be determined by all sources, not just those with good descriptions
        out.setPotentialSources(rawVulns);

        dbh.insertOrUpdateVulnerabilityFull(out);

        logger.info("Finished job for cveId " + out.getCveId());


        List<String> outList = new ArrayList<>();
        // PNE team no longer wants a message for every job, just one big message when they're all done
//        if (out.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.NEW || out.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.UPDATED){
//            outList.add(out.getCveId());
//            messenger.sendPNEMessage(outList);
//        }

        return out;
    }

    private void updateNvdMitre() {
        nvdController.updateNvdTables();
        mitreController.updateMitreTables();
    }

    private Set<CompositeVulnerability> attachNvdMitre(Set<CompositeVulnerability> newVulns) {
        Set<CompositeVulnerability> affected = new HashSet<>();
        affected.addAll(nvdController.compareWithNvd(newVulns));
        affected.addAll(mitreController.compareWithMitre(newVulns));
        return affected;
    }

    public void setDbh(DatabaseHelper db){
        dbh = db;
    }

    public void setReconciler(Reconciler rc){
        reconciler = rc;
    }

    public void setCveCharacterizer(CveCharacterizer ch){
        cveCharacterizer = ch;
    }
}
