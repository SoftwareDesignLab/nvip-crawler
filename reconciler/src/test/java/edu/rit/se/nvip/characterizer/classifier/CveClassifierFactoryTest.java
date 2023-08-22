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