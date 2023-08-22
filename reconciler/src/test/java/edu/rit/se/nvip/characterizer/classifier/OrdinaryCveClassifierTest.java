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

import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.junit.Test;
import weka.classifiers.Classifier;
import weka.classifiers.meta.Vote;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SparseInstance;

import java.nio.file.Paths;
import java.text.NumberFormat;
import java.util.ArrayList;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OrdinaryCveClassifierTest {

//test to make sure you can properly change the classifier if wanted
    @Test
    public void testResetClassifier() {
        OrdinaryCveClassifier ordinaryCveClassifier = new OrdinaryCveClassifier();
        assertEquals(ordinaryCveClassifier.classifier.getClass(), Vote.class);
        ordinaryCveClassifier.resetClassifier(new RandomForest());
        assertEquals(ordinaryCveClassifier.classifier.getClass(), RandomForest.class);
    }

    //tests the predict method
    @Test
    public void testPredict() throws Exception {
        Instances mockInstances = mock(Instances.class);
        Attribute mockAttr = mock(Attribute.class);
        Classifier mockClass = mock(Classifier.class);
        NumberFormat mockFormat = mock(NumberFormat.class);
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");
        OrdinaryCveClassifier ordinaryCveClassifier = new OrdinaryCveClassifier(new RandomForest(), preProcessedTrainingDataFile);

        Instance newInstance = new SparseInstance(8492);
        ordinaryCveClassifier.setMyInstances(mockInstances);
        when(mockInstances.numAttributes()).thenReturn(8492);
        when(mockInstances.numClasses()).thenReturn(1, 3);
        when(mockInstances.classAttribute()).thenReturn(mockAttr);
        when(mockAttr.value(anyInt())).thenReturn("mock");
        ArrayList<String[]> prediction = ordinaryCveClassifier.predict(newInstance, false);
        ordinaryCveClassifier.setClassifier(mockClass);
        ordinaryCveClassifier.setFormatter(mockFormat);
        when(mockClass.distributionForInstance(any(Instance.class))).thenReturn(new double[]{0.1, 1.0, 2.0, 0.2});
        when(mockClass.classifyInstance(any(Instance.class))).thenReturn(1.0);
        when(mockFormat.format(anyLong())).thenReturn("mock long");
        ArrayList<String[]> prediction2 = ordinaryCveClassifier.predict(newInstance, false);
        assertEquals(1, prediction.size());
        assertEquals(1, prediction2.size());

    }
}