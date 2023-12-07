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

import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletableFuture;

public class RequestWrapper implements Comparable<RequestWrapper> {
    ChatCompletionRequest request;
    CompletableFuture<ChatCompletionResult> futureResult;
    RequestorIdentity requestor;
    int priority;
    public RequestWrapper(ChatCompletionRequest request, CompletableFuture<ChatCompletionResult> futureResult, RequestorIdentity requestor, int priority) {
        this.request = request;
        this.futureResult = futureResult;
        this.requestor = requestor;
        this.priority = priority;
    }

    @Override
    public int compareTo(@NotNull RequestWrapper o) {
        if (this.requestor == o.requestor) {
            return this.priority - o.priority;
        }
        return this.requestor.compareTo(o.requestor);
    }
}
