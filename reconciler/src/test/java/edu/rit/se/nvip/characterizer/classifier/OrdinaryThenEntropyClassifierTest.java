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
import org.mockito.MockedStatic;
import weka.classifiers.meta.Vote;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.Instance;
import weka.core.Instances;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.AddValues;

import java.nio.file.Paths;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class OrdinaryThenEntropyClassifierTest {
    //tests that the train model function works with the training data info
    @Test
    void trainMLModel() {
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        OrdinaryThenEntropyClassifier ordinaryThenEntropyClassifier = new OrdinaryThenEntropyClassifier(new Vote(), preProcessedTrainingDataFile);
        ordinaryThenEntropyClassifier.trainMLModel();

        assertEquals(293, ordinaryThenEntropyClassifier.myInstances.size());

    }

    //tests the predict method to make sure there are 2 strings in the array
    @Test
    void predict() {
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        OrdinaryThenEntropyClassifier ordinaryThenEntropyClassifier = new OrdinaryThenEntropyClassifier(new Vote(), preProcessedTrainingDataFile);

        assertEquals(2, ordinaryThenEntropyClassifier.predict("test,test", false).size());

    }

    //tests the classify method to make sure there are 2 strings in the array
    @Test
    void classify() {
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        OrdinaryThenEntropyClassifier ordinaryThenEntropyClassifier = new OrdinaryThenEntropyClassifier(new Vote(), preProcessedTrainingDataFile);
        Instance currentInstance = ordinaryThenEntropyClassifier.createInstanceFromCommaSeparatedAttribs("mock,attr", true);


        assertEquals(2,  ordinaryThenEntropyClassifier.classify(new Vote(), currentInstance, false).size());
    }

    //tests that the createInstance function properly creates and instance
    @Test
    void createInstanceFromCommaSeparatedAttribsTest() throws Exception {
        AddValues mockAddValues = mock(AddValues.class);
        Instances mockInstances = mock(Instances.class);
        Attribute mockAtr = mock(Attribute.class);
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        OrdinaryThenEntropyClassifier ordinaryThenEntropyClassifier = new OrdinaryThenEntropyClassifier(new Vote(), preProcessedTrainingDataFile);
        ordinaryThenEntropyClassifier.setAddValueFilter(mockAddValues);

        MockedStatic<Filter> mockFilter = mockStatic(Filter.class);
        when(mockAddValues.setInputFormat(any(Instances.class))).thenReturn(true);
        mockFilter.when(() -> Filter.useFilter(any(Instances.class), any(Filter.class))).thenReturn(mockInstances);
        when(mockInstances.classAttribute()).thenReturn(mockAtr);
        when(mockAtr.indexOfValue(anyString())).thenReturn(0);
        Instance currentInstance = ordinaryThenEntropyClassifier.createInstanceFromCommaSeparatedAttribs("abil,abil", false);
        mockFilter.close();

        assertNotNull(currentInstance);
    }

    @Test
    void resetClassifierTest(){
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        OrdinaryThenEntropyClassifier ordinaryThenEntropyClassifier = new OrdinaryThenEntropyClassifier(new Vote(), preProcessedTrainingDataFile);

        ordinaryThenEntropyClassifier.resetClassifier(new RandomForest());

        assertTrue(ordinaryThenEntropyClassifier.classifier instanceof RandomForest);
    }
}