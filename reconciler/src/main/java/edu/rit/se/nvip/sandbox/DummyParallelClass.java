package edu.rit.se.nvip.sandbox;

import java.util.HashSet;
import java.util.Set;

public class DummyParallelClass {

    public static void main(String[] args) {
        DummyParallelClass dummyParallel = new DummyParallelClass();

        // Create a set of jobs
        Set<String> jobs = new HashSet<>();
        jobs.add("1");
        jobs.add("2");

        dummyParallel.runJobsInHalfParallel(jobs);
    }

    public void runJobsInHalfParallel(Set<Integer> jobs) {
        for (Integer job : jobs) { //for each job
            Thread thread1 = new Thread(() -> { //thread that does step 1
                step1(job);
            });

            Thread thread2 = new Thread(() -> { //thread that does step 2
                step2(job);
            });

            thread1.start(); //do step 1

            try {
                thread1.join(); //wait for step 1 to end
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }

            thread2.start(); //do step 2

        }
    }

    public void step1(int job) { //mock filtering
        System.out.println("step 1 started for job " + job);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

    }

    public void step2(int job) { //mock reconciling
        System.out.println("step 2 started for job " + job);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
//        System.out.println("step 2 finished for job " + job);
    }
}