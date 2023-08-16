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
import org.apache.commons.io.FileUtils;
import org.junit.Test;
import edu.rit.se.nvip.automatedcvss.preprocessor.CvePreProcessor;
import org.mockito.MockedStatic;
import org.powermock.core.classloader.annotations.PrepareForTest;
import weka.core.Instance;
import weka.core.SparseInstance;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class EntropyBasedCveClassifierTest {

    @Test
    public void testTrainMLModel() throws IOException {
        MockedStatic<FileUtils> mocked = mockStatic(FileUtils.class);
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-edu.rit.se.nvip.process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");
        mocked.when(() -> FileUtils.readFileToString(any(File.class))).thenReturn("mocked, content");
        EntropyBasedCveClassifier entropyBasedCveClassifier = new EntropyBasedCveClassifier(preProcessedTrainingDataFile);
        entropyBasedCveClassifier.trainMLModel();

        assertEquals(entropyBasedCveClassifier.histograms.size(), 1);
        mocked.close();
    }

    @Test
    public void testPredictIncorrectNumAttributes() {
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-edu.rit.se.nvip.process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        EntropyBasedCveClassifier entropyBasedCveClassifier = new EntropyBasedCveClassifier(preProcessedTrainingDataFile);

        Instance newInstance = new SparseInstance(293);
        ArrayList newList = entropyBasedCveClassifier.predict(newInstance, false);
        assertEquals(0, newList.size());
    }

    @Test
    public void testPredict() {
        String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

        // pre-edu.rit.se.nvip.process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");
        EntropyBasedCveClassifier entropyBasedCveClassifier = new EntropyBasedCveClassifier(preProcessedTrainingDataFile);
        String cveDesc = "7.2 HIGH9.0 HIGHCVE-2020-11544 Ã¢â‚¬â€� An issue was discovered in Project Worlds Official Car Rental System 1. It allows the admin user to run commands on the server with their account because the upload section on the file-manager page contains an arbitrary file upload vulnerability via... read CVE-2020-11544 Published: April 06, 2020; 12:15:13 PM -04:00 CVE-2020-11544read CVE-2020-11544V3.1:7.2 HIGH6.5 MEDIUM";

        CvePreProcessor cvePreProcessor = new CvePreProcessor(true);
        String cveDescProcessed = cvePreProcessor.preProcessLine(cveDesc);

        Map<String, ArrayList<String[]>> prediction = new HashMap<String, ArrayList<String[]>>();

        entropyBasedCveClassifier.trainMLModel();
        ArrayList<String[]> predictionFromClassifier = entropyBasedCveClassifier.predict(cveDescProcessed, true);
        String vdoNounGroup = entropyBasedCveClassifier.getCveClassifierName();
        prediction.put(vdoNounGroup, predictionFromClassifier);

        assertEquals(1, prediction.size());
    }
}
