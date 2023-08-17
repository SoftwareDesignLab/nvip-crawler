package edu.rit.se.nvip.automatedcvss.preprocessor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PreProcStemmerTest {

    @Test
    void setNextPreProcessor() {
        PreProcStemmer preProcStemmer = new PreProcStemmer();

        PreProcessor pre = preProcStemmer.setNextPreProcessor(new PreProcStemmer());

        assertTrue(pre == preProcStemmer);
    }
}