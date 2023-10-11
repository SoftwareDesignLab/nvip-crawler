package edu.rit.se.nvip.model;

public class SSVC {
    private enum EXPLOIT_STATUS {
        NONE, POC, ACTIVE
    }
    private final boolean automatable;
    private final EXPLOIT_STATUS exploitStatus;
    private final boolean technicalImpact;

    public SSVC(boolean automatable, EXPLOIT_STATUS exploitStatus, boolean technicalImpact) {
        this.automatable = automatable;
        this.exploitStatus = exploitStatus;
        this.technicalImpact = technicalImpact;
    }
}
