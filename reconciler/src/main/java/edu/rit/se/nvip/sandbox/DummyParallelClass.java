package edu.rit.se.nvip.sandbox;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class DummyParallelClass {
    private BlockingQueue<Integer> queue1;
    private BlockingQueue<Integer> queue2;
    private final Object key = new Object();

    public DummyParallelClass() {
        this.queue1 = new LinkedBlockingQueue<>();
        this.queue2 = new LinkedBlockingQueue<>();
    }

    public static void main(String[] args) {
        DummyParallelClass dummyParallel = new DummyParallelClass();

        // Create a set of jobs
        Set<Integer> jobs = new HashSet<>();
        jobs.add(1);
        jobs.add(2);
        jobs.add(3);

        dummyParallel.runJobsInHalfParallel(jobs);
    }

    public void runJobsInHalfParallel(Set<Integer> jobs) {
        for (Integer job : jobs) { //for each job
            Thread thread1 = new Thread(() -> { //thread that does step 1
                synchronized (key) {
                    step1(job);
                }
            });

            Thread thread2 = new Thread(() -> { //thread that does step 2
                synchronized (key) {
                    step2(job);
                }
            });

            thread1.start(); //do step 1

            try {
                thread1.join(); //wait for step 1 to complete
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }

            thread2.start(); //start step 2

            try {
                thread2.join(); //wait for step 2 to complete
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public void step1(int job) { //filtering
        System.out.println("step 1 started for job " + job);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public void step2(int job) { //reconciling
        System.out.println("step 2 started for job " + job);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        System.out.println("step 2 finished for job " + job);
    }
}