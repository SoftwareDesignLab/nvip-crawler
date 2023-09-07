package edu.rit.se.nvip;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.filter.*;
import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.mitre.MitreCveController;
import edu.rit.se.nvip.model.*;
import edu.rit.se.nvip.nvd.NvdCveController;
import edu.rit.se.nvip.reconciler.Reconciler;
import edu.rit.se.nvip.reconciler.ReconcilerFactory;
import edu.rit.se.nvip.reconciler.VulnBuilder;
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
    private FilterChain filterChain;
    private Messenger messenger = new Messenger();
    private CveCharacterizer cveCharacterizer;
    private NvdCveController nvdController;
    private MitreCveController mitreController;


    public void initialize(){
        this.dbh = DatabaseHelper.getInstance();
        filterChain = new FilterChain(FilterChain.localFilters(), true, true);
        filterChain.appendFilters(ReconcilerEnvVars.getFilterList());
        this.reconciler = ReconcilerFactory.createReconciler(ReconcilerEnvVars.getReconcilerType());
        this.reconciler.setKnownCveSources(ReconcilerEnvVars.getKnownSourceMap());
        if(nvdController == null) {
            this.nvdController = new NvdCveController();
            this.nvdController.createDatabaseInstance();
        }
        if(mitreController == null) {
            this.mitreController = new MitreCveController();
            this.mitreController.initializeController();
        }
    }

    public void main(Set<String> cveIds, boolean userOverride) {
        logger.info(cveIds.size() + " jobs found for reconciliation");
        Set<CompositeVulnerability> reconciledVulns = new HashSet<>();


        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        //characterizer initialization
        CharacterizeTask cTask = new CharacterizeTask();
        Future<CveCharacterizer> futureCharacterizer = executor.submit(cTask);

        //set up reconcile job tasks, map from cve id to future
        Map<String, Future<CompositeVulnerability>> futures = new HashMap<>();
        for (String cveId : cveIds) {
            ReconcileTask task = new ReconcileTask(cveId, userOverride);
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

        Set<CompositeVulnerability> newOrUpdated = reconciledVulns.stream()
                .filter(v -> v.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.NEW ||
                        v.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.UPDATED)
                .collect(Collectors.toSet());

        //PNE team changed their mind about streaming jobs as they finish, they now just want one big list
        messenger.sendPNEMessage(newOrUpdated.stream().map(CompositeVulnerability::getCveId).collect(Collectors.toList()));

        logger.info("Starting NVD/MITRE comparisons");
        updateNvdMitre(); // todo this could be done from the start asynchronously, but attaching shouldn't happen until it's done
        Set<CompositeVulnerability> inNvdOrMitre = attachNvdMitre(reconciledVulns.stream()
                .filter(v -> v.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.NEW)
                .collect(Collectors.toSet()));
        dbh.insertTimeGapsForNewVulns(inNvdOrMitre);

        logger.info("Updating runstats");
        dbh.insertRun(new RunStats(reconciledVulns));

        logger.info("Starting characterization");
        //run characterizer
        if (ReconcilerEnvVars.getDoCharacterization()) {
            //wait for characterizer task to complete
            try {
                if(cveCharacterizer == null) {
                    cveCharacterizer = futureCharacterizer.get();
                }
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException(e);
            }
            characterizeCVEs(reconciledVulns);
            Set<CompositeVulnerability> recharacterized = reconciledVulns.stream()
                    .filter(CompositeVulnerability::isRecharacterized).collect(Collectors.toSet());

            dbh.insertCvssBatch(recharacterized);
            dbh.insertVdoBatch(recharacterized);
        }
        // PNE team no longer wants a finish message
        //messenger.sendPNEFinishMessage();
    }


    private class ReconcileTask implements Callable<CompositeVulnerability> {
        private final String cveId;
        private final boolean userOverride;
        public ReconcileTask(String cveId, boolean userOverride) {
            this.cveId = cveId;
            this.userOverride = userOverride;
        }

        @Override
        public CompositeVulnerability call() {
            try {
                return handleReconcilerJob(cveId, userOverride);
            } catch (Exception ex) {
                logger.error("Error encountered while reconciling {}", cveId);
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
                return new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], ReconcilerEnvVars.getCharacterizationApproach(), ReconcilerEnvVars.getCharacterizationMethod());
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

    private CompositeVulnerability handleReconcilerJob(String cveId, boolean userOverride) {
        // pull data
        Set<RawVulnerability> allRawVulns = dbh.getRawVulnerabilities(cveId);
        // get an existing vuln from prior reconciliation if one exists
        CompositeVulnerability existing = dbh.getCompositeVulnerability(cveId);
        // run filters and reconcile, or try a user override
        VulnBuilder vb = new VulnBuilder(cveId, existing, allRawVulns);
        CompositeVulnerability out;
        if (userOverride) {
            try {
                out = vb.overrideWithUser();
            } catch (VulnBuilder.VulnBuilderException ex) {
                logger.error("An error occurred while attempting a user override for cve {}\n{}", cveId, ex.getMessage());
                return null;
            }
        } else {
            out = vb.filterAndBuild(filterChain, reconciler);
        }
        dbh.updateFilterStatus(out.getChangedSources());

        dbh.insertOrUpdateVulnerabilityFull(out, ReconcilerEnvVars.getInputMode().equals("db"));

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
    public void setFilterChain(FilterChain fc){
        filterChain = fc;
    }
    public void setMessenger(Messenger m){
        messenger = m;
    }
    public void setNvdController(NvdCveController nvd){
        nvdController = nvd;
    }
    public void setMitreController(MitreCveController mit){
        mitreController = mit;
    }
    public void setCveCharacterizer(CveCharacterizer ch){
        cveCharacterizer = ch;
    }
}
