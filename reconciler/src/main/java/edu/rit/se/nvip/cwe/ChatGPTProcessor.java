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
    private static final String SYS_MESSAGE = String.format("You are a tool designed to map CWEs to a given CVE description. " +
            "A user will send a list of CWEs with their IDs and a CVE description your job is to determine which of the CWEs match the CVE. " +
            "If you believe none match respond with simply: \"NONE\" otherwise respond in a comma separated list of each CWE ID you believe matches");
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
    private String askChatGPT(Set<CWE.CWETree> candidates, CompositeVulnerability vuln){
        StringBuilder cwes = new StringBuilder();
        for (CWE.CWETree tree : candidates) {
            cwes.append(tree.getRoot().getId()).append(": ").append(tree.getRoot().getName()).append(", ");
        }
        String chatMessage = "CWEs: \n" + cwes + "\n CVE Description: \n" + vuln.getDescription();
        return callModel(chatMessage);
    }
    private Set<CWE.CWETree> parseResponse(Set<CWE.CWETree> candidates, String response){
        Set<CWE.CWETree> list = new HashSet<>();
        if (response.equals("NONE")){
            return list;
        }
        String[] cweIds = response.split(",");
        for (String id : cweIds){
            for(CWE.CWETree cweTree : candidates){ //what goes here
                if (cweTree.getRoot().getId() == Integer.parseInt(id)){
                    list.add(cweTree);
                }
            }
        }
        return list;
    }
    private Set<CWE.CWETree> whichMatchHelper(Set<CWE.CWETree> candidates, CompositeVulnerability vuln) {
        if (candidates.isEmpty()) {
            return new HashSet<>();
        }
        String response = askChatGPT(candidates, vuln);
        Set<CWE.CWETree> matches = parseResponse(candidates, response);
        Set<CWE.CWETree> out = new HashSet<>();
        for (CWE.CWETree match : matches) {
            out.addAll(whichMatchHelper(match.getSubtrees(), vuln));
        }
        return out;
    }

    public Set<CWE> assignCWEs(CompositeVulnerability vuln) {

        CWE.CWEForest forest = new CWE.CWEForest(); // builds the forest
        Set<CWE.CWETree> trees = whichMatchHelper(forest.getTrees(), vuln);
        Set<CWE> out = new HashSet<>();
        for (CWE.CWETree tree : trees) {
            out.add(tree.getRoot());
        }
        return out;
    }


}
