package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.ReconcilerController;
import edu.rit.se.nvip.messager.Messager;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SandboxMessenger extends Messager {

    public static void main(String[] args) {
        main();
    }
    public static void main() {
        SandboxMessenger mess = new SandboxMessenger();
        ReconcilerController recCon = new ReconcilerController();

        List<String> ids = mess.waitForCrawlerMessage(3600); //wait for crawler message
        Set<String> setIds = new HashSet<>(ids); //convert list to set

        recCon.main(setIds); //send set to ReconMain




    }
}
