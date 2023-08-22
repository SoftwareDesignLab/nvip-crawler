package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.ReconcilerController;
import edu.rit.se.nvip.model.RawVulnerability;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ReconcilerTests {

    private static DatabaseSandbox dbh = DatabaseSandbox.getInstance();
    private List<RawVulnerability> prevPassedHigh;
    private List<RawVulnerability> prevPassedLow;
    private List<RawVulnerability> newHighPass;
    private List<RawVulnerability> newHighFail;
    private List<RawVulnerability> newLowPass;
    private List<RawVulnerability> newLowFail;
    private int ids = 0;


    public static void main(String[] args) {
        dbh.resetDB();
        ReconcilerTests rec = new ReconcilerTests();
        rec.runReconciler(0,0,0,2,1,1);
    }

    public void runReconciler(int previouslyPassedHighPrio, int previouslyPassedLowPrio, int numNewHighPrioPassing, int numNewHighPrioFailing, int numNewLowPrioPassing, int numNewLowPrioFailing){
        List<RawVulnerability> run1 = new ArrayList<>();
        List<RawVulnerability> run2 = new ArrayList<>();
        ReconcilerController recCon = new ReconcilerController();
        recCon.initialize();
        if (previouslyPassedHighPrio > 0){
            prevPassedHigh = genRawVulns(previouslyPassedHighPrio, true, false);
            run1.addAll(prevPassedHigh);
        }
        if(previouslyPassedLowPrio > 0){
            prevPassedLow = genRawVulns(previouslyPassedLowPrio, false, false);
            run1.addAll(prevPassedLow);
        }
        for (RawVulnerability raw : run1){
            dbh.insertRawVuln(raw);
        }
        Set<String> runSet = new HashSet<>();
        runSet.add("CVE-2023-12345");
        if (!run1.isEmpty()){
            //run the crawler
            recCon.main(runSet);
        }

        if (numNewHighPrioPassing > 0){
            newHighPass = genRawVulns(numNewHighPrioPassing, true, false);
            run2.addAll(newHighPass);
        }
        if (numNewHighPrioFailing > 0){
            newHighFail = genRawVulns(numNewHighPrioFailing, true, true);
            run2.addAll(newHighFail);
        }
        if (numNewLowPrioPassing > 0){
            newLowPass = genRawVulns(numNewLowPrioPassing, false, false);
            run2.addAll(newLowPass);
        }
        if (numNewLowPrioFailing > 0){
            newLowFail = genRawVulns(numNewLowPrioFailing, false, true);
            run2.addAll(newLowFail);
        }


        for (RawVulnerability raw : run2){
            dbh.insertRawVuln(raw);
        }
        //run the crawler
        recCon.main(runSet);
    }

    private RawVulnerability genRawVuln(int id, boolean isHighPrio, boolean isFailing){
        ids++;
        if (isHighPrio && isFailing){
            return new RawVulnerability(id, "CVE-2023-"+id, "CVE-2023-"+id, new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "www.google.com/"+ids, RawVulnerability.SourceType.CNA.getType(), 0);
        }else if(isHighPrio){
            return new RawVulnerability(id, "CVE-2023-"+id, "Test description that will pass filters"+ids, new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "www.google.com/"+ids, RawVulnerability.SourceType.CNA.getType(), 0);
        }else if(isFailing){
            return new RawVulnerability(id, "CVE-2023-"+id, "CVE-2023-"+id, new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "www.google.com/"+ids, RawVulnerability.SourceType.OTHER.getType(), 0);
        }
        return new RawVulnerability(id, "CVE-2023-"+id, "Test description that will pass filters"+ids, new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "www.google.com/"+ids);
    }

    private List<RawVulnerability> genRawVulns(int num, boolean isHighPrio, boolean isFailing){
        List<RawVulnerability> rawVulns = new ArrayList<>();
        while(num > 0){
            rawVulns.add(genRawVuln(12345, isHighPrio, isFailing));
            num--;
        }
        return rawVulns;
    }
}
