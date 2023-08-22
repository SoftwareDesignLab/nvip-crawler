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