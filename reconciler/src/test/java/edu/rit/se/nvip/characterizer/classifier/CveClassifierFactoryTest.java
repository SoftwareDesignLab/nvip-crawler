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

package edu.rit.se.nvip.characterizer.classifier;

import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.junit.jupiter.api.Test;
import weka.classifiers.functions.SMO;
import weka.classifiers.meta.Vote;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;

import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class CveClassifierFactoryTest {

    //Confirms classifiers get set correctly for OrdinaryCveClassifiers
    @Test
    void getCveClassifier() {
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        CveClassifierFactory factory = new CveClassifierFactory();

        OrdinaryCveClassifier smoOrd = (OrdinaryCveClassifier) factory.getCveClassifier("ML", "SVM", preProcessedTrainingDataFile);
        OrdinaryCveClassifier j48Ord = (OrdinaryCveClassifier) factory.getCveClassifier("ML", "DT", preProcessedTrainingDataFile);
        OrdinaryCveClassifier randomForOrd = (OrdinaryCveClassifier) factory.getCveClassifier("ML", "RF", preProcessedTrainingDataFile);
        OrdinaryCveClassifier voteOrd = (OrdinaryCveClassifier) factory.getCveClassifier("ML", "Vote", preProcessedTrainingDataFile);

        assertTrue(smoOrd.classifier instanceof SMO);
        assertTrue(j48Ord.classifier instanceof J48);
        assertTrue(randomForOrd.classifier instanceof RandomForest);
        assertTrue(voteOrd.classifier instanceof Vote);
    }
}