package edu.rit.se.nvip.filter;

public class FilterResult {
    private final FilterStatus status;
    private final String failedAt;

    public FilterResult(FilterStatus status, String failedAt) {
        this.status = status;
        this.failedAt = failedAt;
    }

    public FilterStatus getStatus() {
        return this.status;
    }

    public String getFailedAt() {
        return this.failedAt;
    }
}
