package edu.rit.se.nvip.model;

import java.util.Arrays;

public class CVSSVector {
    private String[] partialCvssVector;
    public CVSSVector(String[] partialCvssVector) {
        this.partialCvssVector = partialCvssVector;
    }

    public CVSSVector(String commaSeparatedCvsVector) {
        this.partialCvssVector = commaSeparatedCvsVector.split(",");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CVSSVector that = (CVSSVector) o;
        return Arrays.equals(partialCvssVector, that.partialCvssVector);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(partialCvssVector);
    }
}
