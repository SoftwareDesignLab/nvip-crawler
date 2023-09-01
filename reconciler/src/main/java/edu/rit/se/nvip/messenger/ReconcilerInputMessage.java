package edu.rit.se.nvip.messenger;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Set;

public class ReconcilerInputMessage {
    private List<String> cveIds;
    private boolean userOverride;
    public ReconcilerInputMessage() {}
    public ReconcilerInputMessage(List<String> cveIds, boolean userOverride) {
        this.cveIds = cveIds;
        this.userOverride = userOverride;
    }
    @JsonProperty("cveIds")
    public List<String> getCveIds() {
        return this.cveIds;
    }
    @JsonProperty("cveIds")
    public void setCveIds(List<String> cveIds) {
        this.cveIds = cveIds;
    }
    @JsonProperty("override")
    public boolean isUserOverride() {
        return this.userOverride;
    }
    @JsonProperty("override")
    public void setUserOverride(boolean override) {
        this.userOverride = override;
    }
}
