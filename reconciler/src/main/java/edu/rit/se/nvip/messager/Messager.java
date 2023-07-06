package edu.rit.se.nvip.messager;

import java.util.List;

public class Messager {

    public Messager() {
        // todo do whatever setup is necessary, do you need any env vars for this?
    }

    public void setRabbit(Object whateverThisNeedsToBe) {
        // todo you might want to have a method like this that you can use to inject a mock for rabbitmq when testing
        // this.rabbit = whateverthisneedstobe
    }

    public List<String> waitForCrawlerMessage() {
        // todo wait for a message in rabbitmq from the crawler
        // todo the message will be a json string containing an array of CVE IDs
        return null;
    }

    public void sendPNEMessage(List<String> ids) {
        // todo send the list of changed/new cve ids to rabbitmq for the product name extractor
        // todo the message must be a json string containing an array of CVE IDs
    }

    private List<String> parseIds(String jsonString) {
        // todo use json libraries to get the ids out of the message
        return null;
    }

    private String genJson(List<String> ids) {
        // todo use json libraries to create a json string
        return null;
    }
}
