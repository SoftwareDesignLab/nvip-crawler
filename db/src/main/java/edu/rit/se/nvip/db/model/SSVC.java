package edu.rit.se.nvip.db.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown=true)
public class SSVC {
    private enum EXPLOIT_STATUS {
        NONE, POC, ACTIVE
    }
    @JsonProperty("automatable")
    private boolean automatable;
    @JsonProperty("exploitStatus")
    private EXPLOIT_STATUS exploitStatus;

    private boolean technicalImpact;

    public boolean isAutomatable() { return automatable; }
    public String getExploitStatus() { return exploitStatus.toString(); }
    public boolean getTechnicalImpact() { return technicalImpact; }

    @JsonProperty("technicalImpact")
    public void setTechnicalImpact(String technicalImpact) {
        this.technicalImpact = technicalImpact.equals("TOTAL");
    }
}
