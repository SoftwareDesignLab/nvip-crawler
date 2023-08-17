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
    @Test
    void pullRepoTest() throws GitAPIException {
        when(fileRepositoryMock.getWorkTree()).thenReturn(new File("path/to/local/repo"));

        boolean result = gitController.pullRepo(false);

        assertTrue(result); // Assert the expected behavior
    }

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
    }
}