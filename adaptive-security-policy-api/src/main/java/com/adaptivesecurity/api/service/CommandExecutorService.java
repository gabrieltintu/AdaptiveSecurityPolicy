package com.adaptivesecurity.api.service;

import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.stream.Collectors;
import com.adaptivesecurity.api.utils.AppConstants;
@Service
public class CommandExecutorService {
    /**
     * Executes a command in the Linux terminal and returns the output.
     *
     * @param command bash command to execute
     * @return command result or the error message
     */
    public String execute(String command) {
        try {
            // bash -c to run the command with all arguments as in the terminal
            ProcessBuilder processBuilder = new ProcessBuilder("bash", "-c", command);

            // errors (stderr) are merged with the standard output (stdout)
            processBuilder.redirectErrorStream(true);

            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = reader.lines().collect(Collectors.joining("\n"));

            int exitCode = process.waitFor();

            if (exitCode != AppConstants.SUCCESS_EXIT_CODE) {
                // You can add logging here in the future; for now, we return the text to know what failed
                return "Warning (Code " + exitCode + "): " + output;
            }

            return output;

        } catch (Exception e) {
            e.printStackTrace();
            return "Internal error executing command: " + e.getMessage();
        }
    }
}