package messenger;

import com.fasterxml.jackson.annotation.JsonProperty;

public class PNEInputJob {
    @JsonProperty("cveId")
    private String cveId;

    @JsonProperty("vulnVersionId")
    private int vulnVersionId;

    public PNEInputJob() {}
    public PNEInputJob(String cveId, int vulnVersionId) {
        this.cveId = cveId;
        this.vulnVersionId = vulnVersionId;
    }

    public String getCveId() {
        return this.cveId;
    }

    public void setCveId(String cveId) {
        this.cveId = cveId;
    }

    public int getVulnVersionId() {
        return this.vulnVersionId;
    }

    public void setVulnVersionId(int vulnVersionId) {
        this.vulnVersionId = vulnVersionId;
    }
}
