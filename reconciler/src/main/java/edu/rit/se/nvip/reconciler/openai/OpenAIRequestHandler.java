/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

package edu.rit.se.nvip.reconciler.openai;

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
    private final PriorityBlockingQueue<RequestWrapper> requestQueue = new PriorityBlockingQueue<>(1000);
    private ExecutorService mainExecutor = Executors.newFixedThreadPool(1);
    private ExecutorService requestExecutor = Executors.newFixedThreadPool(5);
    private static OpenAIRequestHandler handler;
    //https://platform.openai.com/account/rate-limits
    private static final ModelType DEFAULT_CHAT_COMPLETION_MODEL = ModelType.GPT_3_5_TURBO;
    private final static double TOKEN_RATE_LIMIT = 90000. / 60;
    private final static double REQUEST_RATE_LIMIT = 3500. /60;
    private final RateLimiter tokenLimiter = RateLimiter.create(TOKEN_RATE_LIMIT);
    private final RateLimiter requestLimiter = RateLimiter.create(REQUEST_RATE_LIMIT);
    private OpenAiService service;
    private int nextPriorityId = 0;
    private Future<?> handlerThreadFuture; // used to eventually cancel the request thread

    static {
        handler = new OpenAIRequestHandler();
    }

    private OpenAIRequestHandler() {
        service = new OpenAiService(ReconcilerEnvVars.getOpenAIKey());
        initExecutors();
    }

    /**
     * shuts down internal executors and threads. Already sent requests will still be fulfilled,
     */
    public void shutdown() {
        //the handleRequests() thread will probably be waiting on a queue.take()
        handlerThreadFuture.cancel(true); // cancelling the future cancels the task
        mainExecutor.shutdown(); // should go right through
        requestExecutor.shutdown(); // lets the request threads finish execution
    }

    private void initExecutors() {
        this.mainExecutor = Executors.newFixedThreadPool(1);
        this.handlerThreadFuture = this.mainExecutor.submit(this::handleRequests);
        this.requestExecutor = Executors.newFixedThreadPool(5);
    }

    /**
     * makes new executors and starts processing requests again
     */
    public void start() {
        if (!mainExecutor.isShutdown() || !requestExecutor.isShutdown()) {
            return;
        }
        initExecutors();
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

    private void handleRequests() {
        while (true) {
            RequestWrapper wrapper;
            try {
                wrapper = requestQueue.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            waitForLimiters(chatCompletionTokenCount(wrapper.request));
            requestExecutor.submit(() -> sendRequest(wrapper));
        }
    }

    private void sendRequest(RequestWrapper requestWrapper) {
        try {
            logger.info("sending msg");
            ChatCompletionResult res = service.createChatCompletion(requestWrapper.request);
            logger.info("sent");
            requestWrapper.futureResult.complete(res);
        } catch (OpenAiHttpException e) {
            Thread.currentThread().interrupt();
            requestWrapper.futureResult.completeExceptionally(e); //todo properly handle this
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
