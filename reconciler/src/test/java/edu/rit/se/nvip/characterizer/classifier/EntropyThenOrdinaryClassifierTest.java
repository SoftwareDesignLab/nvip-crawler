/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.characterizer.classifier;

import edu.rit.se.nvip.divergence.VdoLabelDistribution;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import jnr.ffi.annotations.In;
import org.junit.Test;
import weka.core.Instance;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EntropyThenOrdinaryClassifierTest {

    @Test
    public void testTrainMLModel() {
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        EntropyThenOrdinaryClassifier entropyBasedCveClassifier = new EntropyThenOrdinaryClassifier(preProcessedTrainingDataFile);
        entropyBasedCveClassifier.trainMLModel();

        assertEquals(entropyBasedCveClassifier.histograms.size(), 4);
    }

    @Test
    public void testClassify(){
        Instance mockInstance = mock(Instance.class);
        Map<String, VdoLabelDistribution> mockHistograms = mock(Map.class);
        OrdinaryCveClassifier mockOrd = mock(OrdinaryCveClassifier.class);
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");
        Map<String, VdoLabelDistribution> mockMap = new HashMap<>();
        VdoLabelDistribution vdo = mock(VdoLabelDistribution.class);
        VdoLabelDistribution vdo2 = mock(VdoLabelDistribution.class);
        mockMap.put("1", vdo);
        mockMap.put("2", vdo2);

        EntropyThenOrdinaryClassifier entropyBasedCveClassifier = new EntropyThenOrdinaryClassifier(preProcessedTrainingDataFile);
        entropyBasedCveClassifier.setHistograms(mockHistograms);
        when(mockHistograms.values()).thenReturn(mockMap.values());
        entropyBasedCveClassifier.setNumOfTopClassesToConsiderForPrediction(1);
        when(vdo.calculateKLDivergence(any(VdoLabelDistribution.class))).thenReturn(1.0, 1.00001);
        when(vdo2.calculateKLDivergence(any(VdoLabelDistribution.class))).thenReturn(2.0, 1.0);
        ArrayList<String[]> prediction = entropyBasedCveClassifier.classify(mockInstance, true);
        when(mockInstance.numAttributes()).thenReturn(1);
        when(mockOrd.predict(any(Instance.class), anyBoolean())).thenReturn(prediction);
        entropyBasedCveClassifier.setOrdinaryCveClassifier(mockOrd);

        ArrayList<String[]> prediction2 = entropyBasedCveClassifier.classify(mockInstance, true);

        assertEquals(2, prediction.size());
        assertEquals(2, prediction2.size());
    }

}