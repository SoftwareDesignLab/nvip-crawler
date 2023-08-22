package edu.rit.se.nvip.automatedcvss.preprocessor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PreProcStemmerTest {

    @Test
    void setNextPreProcessor() {
        //not much to test here, but confirmed the settor works as expected
        PreProcStemmer preProcStemmer = new PreProcStemmer();

        PreProcessor pre = preProcStemmer.setNextPreProcessor(new PreProcStemmer());

        assertTrue(pre == preProcStemmer);
    }
}