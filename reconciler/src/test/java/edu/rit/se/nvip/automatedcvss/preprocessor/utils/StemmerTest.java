package edu.rit.se.nvip.automatedcvss.preprocessor.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StemmerTest {

    @Test
    void addTest() {
        Stemmer stemmer = new Stemmer();
        int count = 55;
        while(count > 0) {
            stemmer.add('c');
            count--;
        }

    }

}