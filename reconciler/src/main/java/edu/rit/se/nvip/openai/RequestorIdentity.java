package edu.rit.se.nvip.openai;

public enum RequestorIdentity {
    RECONCILE(0),
    FILTER(1),
    ANON(2);
    final int priority;
    RequestorIdentity(int priority) {
        this.priority = priority;
    }
}
