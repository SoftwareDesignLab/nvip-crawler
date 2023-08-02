package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.openai.OpenAIProcessor;
import edu.rit.se.nvip.openai.RequestorIdentity;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;

public class openaipythonapptest {
    public static void main(String[] args) {
        OpenAIProcessor op = new OpenAIProcessor();
        int count = 5;
        while(count > 0){
            op.sendRequest("\"You are a calculator, respond with just the result of the given equation\"", "2+" + count, 0.0, RequestorIdentity.ANON);
            System.out.println(op.getResponse());
            count--;
        }
    }
}
