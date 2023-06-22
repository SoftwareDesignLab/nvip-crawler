package edu.rit.se.nvip.reconciler;

import edu.rit.se.nvip.model.CompositeDescription;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Set;

import static edu.rit.se.nvip.model.CompositeDescription.equivalentBuildStrings;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class
ReconcilerTest {

    private final String dummyCveId;
    private final int dummyId;
    private final String dummyDescription;
    private final long dummyMillis;
    private final Timestamp dummyDescCreate;
    private final String dummyBuildString;
    private final Timestamp dummyPub;
    private final Timestamp dummyMod;
    private final Timestamp dummyCreate;

    ReconcilerTest() {
        this.dummyCveId = "CVE-xxxx-xxx";
        this.dummyId = 1;
        this.dummyDescription = "description";
        this.dummyMillis = System.currentTimeMillis();
        this.dummyPub = offset(0);
        this.dummyMod = offset(3);
        this.dummyCreate = offset(2);
        this.dummyDescCreate = offset(4);
        this.dummyBuildString = "((1,2),3)";
    }

    private RawVulnerability genRawVuln(int id) {
        return new RawVulnerability(id, dummyCveId, "description"+id, offset(-id), offset(id), offset(-10), "website"+id );
    }
    private Set<RawVulnerability> genRawVulns(int size, int startId) {
        Set<RawVulnerability> out = new LinkedHashSet<>();
        for (int i = 0; i < size; i++) {
            out.add(genRawVuln(i+startId));
        }
        return out;
    }
    private CompositeDescription genCompDes(String buildString, int nSources) {
        return new CompositeDescription(dummyId, dummyCveId, dummyDescription, dummyDescCreate, buildString, genRawVulns(nSources, 1));
    }
    private CompositeVulnerability genVuln(String buildString, int nSources) {
        return new CompositeVulnerability(dummyCveId, dummyId, genCompDes(buildString, nSources), dummyPub, dummyMod, dummyCreate);
    }
    private CompositeVulnerability genVuln() {
        return genVuln(dummyBuildString, 3);
    }

    private Timestamp offset(int nHours) {
        return new Timestamp(dummyMillis + nHours*3600L*1000);
    }

    private Reconciler dummyReconciler(Reconciler.MergeStrategy mergeStrategy) {
        return new Reconciler() {

            @Override
            public MergeStrategy getMergeStrategy(CompositeVulnerability existingVuln, Set<RawVulnerability> newVulns) {
                return mergeStrategy;
            }

            @Override
            public String bulkUpdateDescription(CompositeVulnerability exitingVuln, Set<RawVulnerability> newVulns) {
                return "";
            }

            @Override
            public String synthDescriptionFromScratch(Set<RawVulnerability> vulns) {
                return "";
            }

            @Override
            public String singleUpdateDescription(CompositeVulnerability oldVuln, RawVulnerability newVuln) {
                return "";
            }
        };
    }

    @Test
    void setKnownCveSources() {
        Reconciler rec = dummyReconciler(Reconciler.MergeStrategy.UPDATE_ONE_BY_ONE);
        rec.setKnownCveSources(new HashMap<String, Integer>());
        // that's all! no public access to the field and it's only used in implementations
    }

    @Test
    void reconcileExistingOneByOne() {
        Reconciler rec = dummyReconciler(Reconciler.MergeStrategy.UPDATE_ONE_BY_ONE);
        CompositeVulnerability existing = genVuln();
        Set<RawVulnerability> newRaws = genRawVulns(2, 4);
        CompositeVulnerability reconciled = rec.reconcile(existing, newRaws);
        assertTrue(equivalentBuildStrings("((((1,2),3),4),5)", reconciled.getBuildString()));
        assertEquals(offset(-5), reconciled.getPublishDate());
        assertEquals(offset(5), reconciled.getLastModifiedDate());
    }

    @Test
    void reconcileNullOneByOne() {
        Reconciler rec = dummyReconciler(Reconciler.MergeStrategy.UPDATE_ONE_BY_ONE);
        CompositeVulnerability existing = null;
        Set<RawVulnerability> newRaws = genRawVulns(2, 4);
        CompositeVulnerability reconciled = rec.reconcile(existing, newRaws);
        assertTrue(equivalentBuildStrings("(4,5)", reconciled.getBuildString()));
        assertEquals(offset(-5), reconciled.getPublishDate());
        assertEquals(offset(5), reconciled.getLastModifiedDate());
    }

    @Test
    void reconcileExistingBulk() {
        Reconciler rec = dummyReconciler(Reconciler.MergeStrategy.UPDATE_BULK);
        CompositeVulnerability existing = genVuln();
        Set<RawVulnerability> newRaws = genRawVulns(4, 4);
        CompositeVulnerability reconciled = rec.reconcile(existing, newRaws);
        assertTrue(equivalentBuildStrings("(((1,2),3),4,5,6,7)", reconciled.getBuildString()));
        assertEquals(offset(-7), reconciled.getPublishDate());
        assertEquals(offset(7), reconciled.getLastModifiedDate());
    }

    @Test
    void reconcileExistingResynth() {
        Reconciler rec = dummyReconciler(Reconciler.MergeStrategy.RESYNTH);
        CompositeVulnerability existing = genVuln();
        Set<RawVulnerability> newRaws = genRawVulns(4, 4);
        CompositeVulnerability reconciled = rec.reconcile(existing, newRaws);
        assertTrue(equivalentBuildStrings("(1,2,3,4,5,6,7)", reconciled.getBuildString()));
        assertEquals(offset(-7), reconciled.getPublishDate());
        assertEquals(offset(7), reconciled.getLastModifiedDate());
    }

    @Test
    void reconcileNullResynth() {
        Reconciler rec = dummyReconciler(Reconciler.MergeStrategy.RESYNTH);
        CompositeVulnerability existing = null;
        Set<RawVulnerability> newRaws = genRawVulns(4, 4);
        CompositeVulnerability reconciled = rec.reconcile(existing, newRaws);
        assertTrue(equivalentBuildStrings("(4,5,6,7)", reconciled.getBuildString()));
        assertEquals(offset(-7), reconciled.getPublishDate());
        assertEquals(offset(7), reconciled.getLastModifiedDate());
    }
}