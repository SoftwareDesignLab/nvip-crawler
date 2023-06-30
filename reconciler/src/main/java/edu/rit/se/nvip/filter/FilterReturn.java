package edu.rit.se.nvip.filter;

public class FilterReturn {
    public int numIn;
    public int numDistinct;
    public int numPassed;
    public FilterReturn(int numIn, int numDistinct, int numPassed) {
        this.numIn = numIn;
        this.numDistinct = numDistinct;
        this.numPassed = numPassed;
    }

    public void add(FilterReturn other) {
        if (other == null) {
            return;
        }
        this.numIn += other.numIn;
        this.numDistinct += other.numDistinct;
        this.numPassed += other.numPassed;
    }
}
