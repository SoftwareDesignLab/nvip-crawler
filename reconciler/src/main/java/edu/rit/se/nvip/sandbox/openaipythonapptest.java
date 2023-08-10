package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.openai.OpenAIProcessor;
import edu.rit.se.nvip.openai.RequestorIdentity;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
/*
    DEVELOPMENT STOPPED 8/10/23 DUE TO HESITATION TO USE CHATGPT/OPENAI
 */
public class openaipythonapptest {
    public static void main(String[] args) throws InterruptedException {
        OpenAIProcessor op = new OpenAIProcessor();
        List<CompletableFuture<String>> list = new ArrayList<>();
        int count = 400;
//        while(count > 0){
//            list.add(op.sendRequest("\"You are a calculator, respond with just the result of the given equation\"", "200+" + count, 0.0, RequestorIdentity.FILTER));
//            list.add(op.sendRequest("\"You are a calculator, respond with just the result of the given equation\"", "20+" + count, 0.0, RequestorIdentity.ANON));
//            list.add(op.sendRequest("\"You are a calculator, respond with just the result of the given equation\"", "2000+" + count, 0.0, RequestorIdentity.RECONCILE));
//            count--;
//        }
        int wordCount = 100;
        StringBuilder string = new StringBuilder();
        while (wordCount > 0){
            string.append("token ");
            wordCount--;
        }

        while(count > 0){
            op.sendRequest("respond Hi to every message you get", string.toString(), 0.0, RequestorIdentity.ANON, 1);
            count--;
        }

        for (CompletableFuture<String> futureString : list) {
            try {
                // Wait for the response with a timeout of 5 seconds
                String response = futureString.get(10, TimeUnit.SECONDS);
                System.out.println(response);
            } catch (TimeoutException e) {
                // Handle timeout exception
                System.out.println("Timeout: " + e);
            } catch (ExecutionException e) {
                // Print the exception details to diagnose the issue
                System.out.println("Error: " + e);
            }
        }
        op.shutdownListener();


    }
}
