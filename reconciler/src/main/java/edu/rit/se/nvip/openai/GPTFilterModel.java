package edu.rit.se.nvip.openai;

import com.theokanning.openai.OpenAiHttpException;
import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import com.theokanning.openai.completion.chat.ChatMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

public class GPTFilterModel {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private static final String MODEL = "gpt-3.5-turbo";
    private static final double TEMP = 0.0;
    private static final String PASS = "0";
    private static final String FAIL = "1";
    private static final String SYS_MESSAGE = String.format("You are a validation engine for vulnerability data scraped from the web." +
            " If a user's message looks like a CVE description without errors, respond with \"%s\" or else \"%s\"", PASS, FAIL);
    private static final String SYS_ROLE = "system";
    private static final String USER_ROLE = "user";
    private OpenAIRequestHandler requestHandler;

    public GPTFilterModel() {
        requestHandler = OpenAIRequestHandler.getInstance();
    }

    public void setRequestHandler(OpenAIRequestHandler handler) {
        this.requestHandler = handler;
    }

    public boolean callModel(String arg) throws OpenAiInvalidReturnException{
        try {
            ChatCompletionRequest request = formRequest(arg);
            Future<ChatCompletionResult> futureRes = requestHandler.createChatCompletion(request, RequestorIdentity.FILTER);
            ChatCompletionResult res = futureRes.get();
            return getAnswer(res);
        } catch (OpenAiHttpException | InterruptedException | ExecutionException ex) {
            logger.error(ex);
            return true; // need a default answer
        }
    }

    public int tokenCount(String description) {
        return requestHandler.chatCompletionTokenCount(formRequest(description));
    }

    private ChatCompletionRequest formRequest(String description) {
        List<ChatMessage> messages = formMessages(description);
        return ChatCompletionRequest.builder().model(MODEL).temperature(TEMP).n(1).messages(messages).maxTokens(1).build();
    }

    private List<ChatMessage> formMessages(String description) {
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(new ChatMessage(SYS_ROLE, SYS_MESSAGE));
        messages.add(new ChatMessage(USER_ROLE, description));
        return messages;
    }

    private boolean getAnswer(ChatCompletionResult res) throws OpenAiInvalidReturnException {
        String answer = res.getChoices().get(0).getMessage().getContent();
        switch (answer) {
            case PASS:
                return true;
            case FAIL:
                return false;
            default:
                throw new OpenAiInvalidReturnException("OpenAi responded with \"" + answer + "\"");
        }
    }

    public static class OpenAiInvalidReturnException extends Exception {
        public OpenAiInvalidReturnException(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class OpenAiException extends Exception {
        public OpenAiException(String errorMessage) {
            super(errorMessage);
        }
    }

    public static void main(String[] args) throws OpenAiInvalidReturnException, InterruptedException {
        GPTFilterModel model = new GPTFilterModel();
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        int a = 0;
        for (int i = 0; i < 5; i++) {
            int finalI = i;
            executor.submit(() -> {
                try {
                    boolean result = model.callModel("testing # " + finalI);
                    System.out.println("trial # " + finalI + " evaluated as " + result);
                } catch (OpenAiInvalidReturnException e) {
                    System.out.println(e.toString());
                }
            });
        }
        executor.shutdown();
        boolean res = executor.awaitTermination(10, TimeUnit.SECONDS);
        System.out.println(res);
        OpenAIRequestHandler.getInstance().shutdown();
    }
}
