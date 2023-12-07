/ **
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
* /

package edu.rit.se.nvip.automatedcvss;

import org.junit.jupiter.api.Test;
import org.python.core.PyList;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;
import org.python.util.PythonObjectInputStream;

import java.text.DecimalFormat;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class CvssScoreCalculatorTest {
    //Tests getting the CVSS score given an array of strings indicating different metrics. Also tested the mean median min and max were found correctly
    private PythonInterpreter mockPython = mock(PythonInterpreter.class);
    private PyObject pyObj = mock(PyObject.class);
    private PyList pyList = mock(PyList.class);
    @Test
    void getCvssScoreJython() {
        doNothing().when(mockPython).exec(anyString());
        doNothing().when(mockPython).execfile(anyString());
        when(mockPython.get(anyString())).thenReturn(pyObj);
        when(pyObj.__call__((any(PyList.class)))).thenReturn(pyList);
        Double[] dblArray = {0.0, 1.0, 2.0, 3.0, 4.0};
        when(pyList.toArray()).thenReturn(dblArray);
        doNothing().when(mockPython).close();
        CvssScoreCalculator cvssScoreCalculator = new CvssScoreCalculator(mockPython);

        String[] strs = {"N", "H", "X", "X", "C", "H", "N", "N"};
        double[] res = cvssScoreCalculator.getCvssScoreJython(strs);

        assertEquals(2.0, res[0]);
        assertEquals(0.0, res[1]);
        assertEquals(4.0, res[2]);
        DecimalFormat df = new DecimalFormat("#.#");
        assertEquals(1.4, Double.parseDouble(df.format(res[3])));

    }

    @Test
    void calculateMedianMinMaxStdDeviation() {
        doNothing().when(mockPython).exec(anyString());
        doNothing().when(mockPython).execfile(anyString());
        when(mockPython.get(anyString())).thenReturn(pyObj);
        doNothing().when(mockPython).close();
        CvssScoreCalculator cvssScoreCalculator = new CvssScoreCalculator(mockPython);
        Double[] doubles = {0.0, 1.0, 2.0, 3.0, 4.0};

        double[] res = cvssScoreCalculator.calculateMedianMinMaxStdDeviation(doubles);

        assertEquals(2.0, res[0]);
        assertEquals(0.0, res[1]);
        assertEquals(4.0, res[2]);
        DecimalFormat df = new DecimalFormat("#.#");
        assertEquals(1.4, Double.parseDouble(df.format(res[3])));
    }

}