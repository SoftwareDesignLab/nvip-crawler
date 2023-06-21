package edu.rit.se.nvip.reconciler.models;

import opennlp.tools.postag.POSModel;
import opennlp.tools.postag.POSTaggerME;
import opennlp.tools.sentdetect.SentenceDetector;
import opennlp.tools.sentdetect.SentenceDetectorME;
import opennlp.tools.sentdetect.SentenceModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class ApacheOpenNLPModel {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    POSTaggerME tagger = null;
    POSModel model = null;
    SentenceModel sentenceModel = null;
    SentenceDetector sentenceDetector = null;
    String modelPath = "nlp/en-pos-perceptron.bin";
    String sentenceModelPath = "nlp/en-sent.bin";

    public void initialize() {
        try {
            InputStream modelStream = this.getClass().getClassLoader().getResourceAsStream(modelPath);
            model = new POSModel(modelStream);
            tagger = new POSTaggerME(model);
            modelStream.close();

            InputStream modelIn = this.getClass().getClassLoader().getResourceAsStream(sentenceModelPath);
            sentenceModel = new SentenceModel(modelIn);
            sentenceDetector = new SentenceDetectorME(sentenceModel);
            modelIn.close();

        } catch (Exception e) {
            logger.error("A serious error has occurred while loading the models for CVE reconciliation! Exiting!" + e.toString());
            System.exit(1);
        }
    }

    public String[] tag(String[] whiteSpaceTokenizerLine) {
        return tagger.tag(whiteSpaceTokenizerLine);
    }

    public String[] sentDetect(String paragraph) {
        return sentenceDetector.sentDetect(paragraph);
    }

}
