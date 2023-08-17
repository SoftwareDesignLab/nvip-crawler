package edu.rit.se.nvip.reconciler.models;

import opennlp.tools.postag.POSModel;
import opennlp.tools.postag.POSTaggerME;
import opennlp.tools.sentdetect.SentenceDetector;
import opennlp.tools.sentdetect.SentenceModel;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.configuration.IMockitoConfiguration;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ApacheOpenNLPModelTest {
    @Mock
    SentenceDetector mockDetector = mock(SentenceDetector.class);
    private ApacheOpenNLPModel apacheOpenNLPModel = new ApacheOpenNLPModel();

    @Test
    void initialize(){

        //apacheOpenNLPModel.initialize();

    }
    @Test
    void tag() {
        POSTaggerME mockTagger = mock(POSTaggerME.class);
        apacheOpenNLPModel.setTagger(mockTagger);
        String sample = "test string";
        String[] response = sample.split(" ");
        apacheOpenNLPModel.tag(response);
    }

    @Test
    void sentDetect() {
        apacheOpenNLPModel.setSentenceDetector(mockDetector);
        String sample = "test string";
        String[] response = sample.split(" ");
        when(mockDetector.sentDetect(anyString())).thenReturn(response);
        apacheOpenNLPModel.sentDetect(sample);
    }
}