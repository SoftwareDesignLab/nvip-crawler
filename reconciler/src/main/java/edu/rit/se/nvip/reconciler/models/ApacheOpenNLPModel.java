/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

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
    public void setSentenceDetector(SentenceDetector sen){
        sentenceDetector = sen;
    }
    public void setTagger(POSTaggerME tag){
        tagger = tag;
    }
}
