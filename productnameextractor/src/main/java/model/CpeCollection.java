package model;

import model.cpe.AffectedProduct;
import model.cve.CompositeVulnerability;

import java.util.List;

public class CpeCollection {

    private CompositeVulnerability cve;

    private List<AffectedProduct> cpes;
    private int cpeSetId;

    public CpeCollection(CompositeVulnerability cve, List<AffectedProduct> cpes) {
        this.cve = cve;
        this.cpes = cpes;
    }

    public CompositeVulnerability getCve() {
        return cve;
    }

    public void setCve(CompositeVulnerability cve) {
        this.cve = cve;
    }

    public List<AffectedProduct> getCpes() {
        return cpes;
    }

    public void setCpes(List<AffectedProduct> cpes) {
        this.cpes = cpes;
    }

    public int getCpeSetId() {
        return this.cpeSetId;
    }

    public void setCpeSetId(int cpeSetId) {
        this.cpeSetId = cpeSetId;
    }
}
