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

package edu.rit.se.nvip.utils;

import org.apache.commons.io.FileUtils;
import org.eclipse.jgit.api.CloneCommand;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.PullCommand;
import org.eclipse.jgit.api.PullResult;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.internal.storage.file.FileRepository;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.lib.StoredConfig;
import org.eclipse.jgit.storage.file.FileBasedConfig;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class GitControllerTest {
    @InjectMocks
    private GitController gitController = new GitController("dummyPath", "dummyRemotePath");

    @Mock
    private Git gitMock = mock(Git.class);
    @Mock
    private PullCommand pullMock = mock(PullCommand.class);
    @Mock
    private PullResult pullResultMock = mock(PullResult.class);

    @Mock
    private FileRepository fileRepositoryMock = mock(FileRepository.class);

    //verifies you can pull a repo without actually pulling it
    @Test
    void pullRepoTest() throws GitAPIException {
        when(fileRepositoryMock.getWorkTree()).thenReturn(new File("path/to/local/repo"));
        Git mockGit = mock(Git.class);
        PullCommand mockPull = mock(PullCommand.class);
        PullResult mockRes = mock(PullResult.class);
        gitController.setGit(mockGit);
        when(mockGit.pull()).thenReturn(mockPull);
        when(mockPull.call()).thenReturn(mockRes);

        boolean result = gitController.pullRepo();

        assertTrue(result); // Assert the expected behavior
    }

    //verifies you can clone a repo without actually cloning it
    @Test
    void cloneRepoTest() throws GitAPIException {
        MockedStatic<Git> mocked = mockStatic(Git.class);
        CloneCommand mockClone = mock(CloneCommand.class);
        Repository mockRepo = mock(Repository.class);
        StoredConfig mockConfig = mock(StoredConfig.class);
        File localFileDir = new File("path/to/local/repo");

        mocked.when(Git::cloneRepository).thenReturn(mockClone);
        mocked.when(() -> Git.open(any(File.class))).thenReturn(gitMock);
        when(mockClone.call()).thenReturn(gitMock);
        when(gitMock.getRepository()).thenReturn(mockRepo);
        when(mockRepo.getConfig()).thenReturn(mockConfig);


        boolean result = gitController.cloneRepo();

        assertTrue(result); // Assert the expected behavior
        mocked.close();
    }
}