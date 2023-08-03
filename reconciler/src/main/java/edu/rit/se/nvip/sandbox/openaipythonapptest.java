package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.openai.OpenAIProcessor;
import edu.rit.se.nvip.openai.RequestorIdentity;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;

public class openaipythonapptest {
    public static void main(String[] args) throws InterruptedException {
        OpenAIProcessor op = new OpenAIProcessor();
        int count = 5;
        while(count > 0){
            op.sendRequest("\"You are a calculator, respond with just the result of the given equation\"", "200+" + count, 0.0, RequestorIdentity.FILTER);
            op.sendRequest("\"You are a calculator, respond with just the result of the given equation\"", "20+" + count, 0.0, RequestorIdentity.ANON);
            op.sendRequest("\"You are a calculator, respond with just the result of the given equation\"", "2000+" + count, 0.0, RequestorIdentity.RECONCILE);
            count--;
        }

        System.out.println(op.getResponse());
        System.out.println(op.getResponse());
        System.out.println(op.getResponse());
    }
}
