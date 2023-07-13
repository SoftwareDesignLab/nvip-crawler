package edu.rit.se.nvip.openai;

import com.google.common.util.concurrent.RateLimiter;
import com.knuddels.jtokkit.Encodings;
import com.knuddels.jtokkit.api.Encoding;
import com.knuddels.jtokkit.api.ModelType;
import com.theokanning.openai.OpenAiHttpException;
import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.model.Model;
import com.theokanning.openai.service.OpenAiService;
import edu.rit.se.nvip.ReconcilerMain;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;

/**
 * Make all chat completion requests through here. If other types of OpenAI requests become necessary, they should be implemented in here so that the rate limit resource is appropriately shared.
 */
public class OpenAIRequestHandler {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private final PriorityBlockingQueue<RequestWrapper> requestQueue = new PriorityBlockingQueue<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(1);
    private static OpenAIRequestHandler handler;
    //https://platform.openai.com/account/rate-limits
    private static final ModelType DEFAULT_CHAT_COMPLETION_MODEL = ModelType.GPT_3_5_TURBO;
    private final static double TOKEN_RATE_LIMIT = 90000. / 60;
    private final static double REQUEST_RATE_LIMIT = 3500. /60;
    private final RateLimiter tokenLimiter = RateLimiter.create(TOKEN_RATE_LIMIT);
    private final RateLimiter requestLimiter = RateLimiter.create(REQUEST_RATE_LIMIT);
    private OpenAiService service;
    private int nextPriorityId = 0;

    static {
        handler = new OpenAIRequestHandler();
    }

    private OpenAIRequestHandler() {
        service = new OpenAiService(ReconcilerEnvVars.getOpenAIKey());
        executor.submit(this::handleRequests); // run handleRequests() in the background
    }

    /**
     * This class does not allow a public constructor because it must remain a singleton in order to guarantee respect for rate limits
     * @return the singleton OpenAIRequestHandler()
     */
    public static OpenAIRequestHandler getInstance() {
        if (handler == null) {
            handler = new OpenAIRequestHandler();
        }
        return handler;
    }

    public void shutdown() {
        this.executor.shutdownNow();
    }

    private void handleRequests() {
        while (true) {
            RequestWrapper wrapper;
            try {
                wrapper = requestQueue.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            waitThenCall(wrapper.request, wrapper.futureResult);
        }
    }

    private void waitThenCall(ChatCompletionRequest request, CompletableFuture<ChatCompletionResult> future) {
        waitForLimiters(chatCompletionTokenCount(request));
        try {
            ChatCompletionResult res = service.createChatCompletion(request);
            future.complete(res);
        } catch (OpenAiHttpException e) {
            Thread.currentThread().interrupt();
            future.completeExceptionally(e); //todo properly handle this
        }
    }

    /**
     * Sets the OpenAiService to request chat completions through. Set this to a mock when testing.
     * @param service
     */
    public void setService(OpenAiService service) {
        // dependency injection allows easier testing
        this.service = service;
    }

    /**
     * Makes a no-cost call to openAI to verify the connection
     * @return true if connected
     */
    public boolean testConnection() {
        // the listModels() includes an API call to account for any fine-tuned models, so this effectively validates the key and connection without actually using any tokens
        try {
            List<Model> models = service.listModels();
            return models.size() > 0;
        } catch (Exception ex) {
            logger.error("Could not connect to OpenAI. Check your internet connection or key");
        }
        return false;
    }

    /**
     * Queues the request for sending
     * @param request the chat completion request in need of handling
     * @return a future object which will be populated when the rate limiters and priority allow
     */
    public Future<ChatCompletionResult> createChatCompletion(ChatCompletionRequest request, RequestorIdentity requestor) {
        CompletableFuture<ChatCompletionResult> future = new CompletableFuture<>();
        RequestWrapper wrapper = new RequestWrapper(request, future, requestor, nextPriorityId++);
        // drop the request in the queue and tell any concerned threads about it
        requestQueue.put(wrapper);
        return future;
    }

    /**
     * Computes the number of tokens this request would use if sent. This method does not make any API calls.
     * @param request the completion request in question
     * @return the number of tokens that will be used (not counting return tokens)
     */
    public int chatCompletionTokenCount(ChatCompletionRequest request) {
        Optional<Encoding> optEnc = Encodings.newDefaultEncodingRegistry().getEncodingForModel(request.getModel());
        Encoding enc = optEnc.orElseGet(() -> Encodings.newDefaultEncodingRegistry().getEncodingForModel(DEFAULT_CHAT_COMPLETION_MODEL));
        return chatCompletionTokenCount(request.getMessages(), enc);
    }

    /**
     * Computes the number of tokens this request would use if sent with the given messages. This method does not make any API calls
     * @param messages a list of ChatMessages to be tokenized
     * @param enc the encoding to use for tokenization
     * @return the number of tokens that would be used in an API call (not counting return tokens)
     */
    public int chatCompletionTokenCount(List<ChatMessage> messages, Encoding enc) {
        // this is not as simple as just tokenizing the openAI query because that query goes through some further processing on their end, adding tokens
        // numbers gotten from https://github.com/openai/openai-cookbook/blob/main/examples/How_to_count_tokens_with_tiktoken.ipynb
        int tokensPerMsg = 4;
        int tokenCount = 0;
        for (ChatMessage msg : messages) {
            tokenCount += tokensPerMsg;
            tokenCount += enc.encode(msg.getContent()).size();
            tokenCount += enc.encode(msg.getRole()).size();
        }
        return tokenCount;
    }

    private void waitForLimiters(int tokens) {
        tokenLimiter.acquire(tokens);
        requestLimiter.acquire(1);
    }
}
