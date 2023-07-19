package edu.rit.se.nvip.cwe;

import com.theokanning.openai.OpenAiHttpException;
import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import com.theokanning.openai.completion.chat.ChatMessage;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.openai.OpenAIRequestHandler;
import edu.rit.se.nvip.openai.RequestorIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class ChatGPTProcessor {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private OpenAIRequestHandler requestHandler;
    private static final String MODEL = "gpt-3.5-turbo";
    private static final double TEMP = 0.0;
    private static final String SYS_MESSAGE = String.format("You will be presented with several CWEs and their IDs followed by a CVE description." +
            " Your job is to provide a list, from the CWEs given to you, of CWE IDs that you think could be involved with the CVE based on the CVE description," +
            " if you believe that none of the given CWEs match then simply respond \"NONE\" otherwise send a comma separated list of CWE Ids that match." +
            " IT MUST BE STRICTLY THE CWE ID NUMBER.");
    private static final String SYS_ROLE = "system";
    private static final String USER_ROLE = "user";
    public ChatGPTProcessor() {
        requestHandler = OpenAIRequestHandler.getInstance();
    }

    public String callModel(String arg) {
        try {
            ChatCompletionRequest request = formRequest(arg);
            Future<ChatCompletionResult> futureRes = requestHandler.createChatCompletion(request, RequestorIdentity.FILTER);
            ChatCompletionResult res = futureRes.get();
            return res.getChoices().get(0).getMessage().getContent();// Return the obtained result

        } catch (OpenAiHttpException | InterruptedException | ExecutionException ex) {
            logger.error(ex);
            return null;
        }
    }
    private ChatCompletionRequest formRequest(String description) {
        List<ChatMessage> messages = formMessages(description);
        return ChatCompletionRequest.builder().model(MODEL).temperature(TEMP).n(1).messages(messages).maxTokens(1000).build();
    }

    private List<ChatMessage> formMessages(String description) {
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(new ChatMessage(SYS_ROLE, SYS_MESSAGE));
        messages.add(new ChatMessage(USER_ROLE, description));
        return messages;
    }
    private List<String> askChatGPT(Set<CWETree> candidates, CompositeVulnerability vuln){
        StringBuilder cwes = new StringBuilder();
        int count = 1;
        List<String> out = new ArrayList<>();
        for (CWETree tree : candidates) {
            cwes.append(tree.getRoot().getId()).append(": ").append(tree.getRoot().getName()).append(", ");
            //logger.info(tree.getRoot().getId());
            if(count % 5 == 0){
                String chatMessage = cwes + " \nCVE Description: \n" + vuln.getDescription();
                String msg = callModel(chatMessage);
                out.addAll(getIdsFromResponse(msg));
                cwes = new StringBuilder();
            }
            count++;
        }
        if (cwes.length() != 0){
            String chatMessage = cwes + " CVE Description: " + vuln.getDescription();
            String finalRun = callModel(chatMessage);
            out.addAll(getIdsFromResponse(finalRun));
        }
        return out;
    }
    private Set<CWETree> parseResponse(Set<CWETree> candidates, List<String> response){
        Set<CWETree> set = new HashSet<>();
        if (response.equals("NONE") || response.equals("DONE")){
            return set;
        }
        //logger.info(response);
        for (String id : response){
            for(CWETree cweTree : candidates){
                try {
                    if(id.equals("NONE") || id.equals("") || id.equals("DONE")){
                        return set;
                    }
                    if (cweTree.getRoot().getId() == Integer.parseInt(id)) {
                        set.add(cweTree);
                    }
                }catch(NumberFormatException e){
                    logger.error("chatGpt sent wrong format");
                    logger.info(id);
                    break;
                }
            }
        }
        return set;
    }
    private Set<CWETree> whichMatchHelper(Set<CWETree> candidates, CompositeVulnerability vuln) {
        if (candidates.isEmpty()) {
            return new HashSet<>();
        }
        List<String> response = askChatGPT(candidates, vuln);
        Set<CWETree> matches = parseResponse(candidates, response);
        Set<CWETree> out = new HashSet<>();
        for (CWETree match : matches) {
            out.addAll(whichMatchHelper(match.getSubtrees(), vuln));
        }
        return out;
    }

    public Set<CWE> assignCWEs(CompositeVulnerability vuln) {

        CWEForest forest = new CWEForest(); // builds the forest
        Set<CWETree> trees = whichMatchHelper(forest.getTrees(), vuln);
        Set<CWE> out = new HashSet<>();
        for (CWETree tree : trees) {
            out.add(tree.getRoot());
        }
        return out;
    }
    private List<String> getIdsFromResponse(String response) {
        String[] parts = response.split(",");
        List<String> out = new ArrayList<>();
        for (String part : parts) {
            String[] finalParts = part.split("CWE-");
            for (String finalPart : finalParts){
                String trimmedPart = finalPart.trim();
                if (trimmedPart.equals("") || trimmedPart.equals("NONE") || trimmedPart.equals("DONE")) continue;
                if (ChatGPTProcessor.isInt(trimmedPart)) {
                    out.add(trimmedPart);
                }
            }
        }
        return out;
    }
    public static boolean isInt(String input) {
        try {
            Integer.parseInt(input);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

}
