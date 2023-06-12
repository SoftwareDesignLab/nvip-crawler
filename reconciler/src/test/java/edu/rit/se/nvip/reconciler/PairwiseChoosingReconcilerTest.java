package reconciler;

import edu.rit.se.nvip.model.CompositeDescription;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PairwiseChoosingReconcilerTest {

    private final String dummyCveId;
    private final int dummyId;
    private final String dummyDescription;
    private final long dummyMillis;
    private final Timestamp dummyDescCreate;
    private final String dummyBuildString;
    private final Timestamp dummyPub;
    private final Timestamp dummyMod;
    private final Timestamp dummyCreate;

    PairwiseChoosingReconcilerTest() {
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

    private PairwiseChoosingReconciler dummyRec(boolean dummyReturn) {
        return new PairwiseChoosingReconciler() {
            @Override
            public boolean reconcileDescriptions(String existingDescription, String newDescription, Set<String> existingSourceDomains, String newSourceDomain) {
                return dummyReturn || existingDescription == null;
            }
        };
    }

    @Test
    void getMergeStrategy() {
        PairwiseChoosingReconciler rec = dummyRec(false);
        Reconciler.MergeStrategy strategy = rec.getMergeStrategy(null, null);
        assertEquals(Reconciler.MergeStrategy.UPDATE_ONE_BY_ONE, strategy);
        strategy = rec.getMergeStrategy(genVuln(), genRawVulns(3, 4));
        assertEquals(Reconciler.MergeStrategy.UPDATE_ONE_BY_ONE, strategy);
    }

    @Test
    void singleUpdateDescription() {
        PairwiseChoosingReconciler rec = dummyRec(false);
        String desc = rec.singleUpdateDescription(genVuln(), genRawVuln(4));
        assertEquals(dummyDescription, desc);
        desc = rec.singleUpdateDescription(null, genRawVuln(4));
        assertEquals("description4", desc);

        rec = dummyRec(true);
        desc = rec.singleUpdateDescription(genVuln(), genRawVuln(4));
        assertEquals("description4", desc);
        desc = rec.singleUpdateDescription(null, genRawVuln(4));
        assertEquals("description4", desc);
    }

    @Test
    void synthDescriptionFromScratch() {
        PairwiseChoosingReconciler rec = dummyRec(false);
        String desc = rec.synthDescriptionFromScratch(genRawVulns(3, 1));
        assertEquals("description1", desc);
        rec = dummyRec(true);
        desc = rec.synthDescriptionFromScratch(genRawVulns(3, 1));
        assertEquals("description3", desc);
    }

    @Test
    void bulkUpdateDescription() {
        PairwiseChoosingReconciler rec = dummyRec(false);
        String desc = rec.bulkUpdateDescription(genVuln(), genRawVulns(3, 4));
        assertEquals(dummyDescription, desc);
        desc = rec.bulkUpdateDescription(null, genRawVulns(3, 4));
        assertEquals("description4", desc);

        rec = dummyRec(true);
        desc = rec.bulkUpdateDescription(genVuln(), genRawVulns(3, 4));
        assertEquals("description6", desc);
        desc = rec.bulkUpdateDescription(null, genRawVulns(3, 4));
        assertEquals("description6", desc);
    }
}