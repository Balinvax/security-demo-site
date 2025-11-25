package com.securitysite.securitydemosite;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class TestSummaryListener implements TestExecutionListener {

    private int total = 0;
    private int passed = 0;
    private int failed = 0;

    private final List<String> failedTests = new ArrayList<>();

    @Override
    public void executionFinished(TestIdentifier testIdentifier,
                                  TestExecutionResult result) {

        if (!testIdentifier.isTest()) return;

        total++;

        if (result.getStatus() == TestExecutionResult.Status.SUCCESSFUL) {
            passed++;
        } else {
            failed++;
            failedTests.add(testIdentifier.getDisplayName());
        }
    }

    @Override
    public void testPlanExecutionFinished(TestPlan testPlan) {

        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        StringBuilder sb = new StringBuilder();
        sb.append("===========================================\n");
        sb.append("        SECURITY TEST AUTOMATION REPORT\n");
        sb.append("===========================================\n");
        sb.append("Timestamp: ").append(timestamp).append("\n");
        sb.append("-------------------------------------------\n");
        sb.append("Total tests: ").append(total).append("\n");
        sb.append("Passed:      ").append(passed).append("\n");
        sb.append("Failed:      ").append(failed).append("\n");
        sb.append("-------------------------------------------\n");

        if (failed > 0) {
            sb.append("FAILED TESTS:\n");
            failedTests.forEach(t -> sb.append(" - ").append(t).append("\n"));
        } else {
            sb.append("✔ ALL TESTS PASSED SUCCESSFULLY\n");
        }

        sb.append("===========================================\n");

        // ensure directory exists
        try {
            new java.io.File("target").mkdirs();
        } catch (Exception ignored) {}

        // write report
        try (PrintWriter out = new PrintWriter(new FileWriter("target/security-test-report.txt"))) {
            out.println(sb);
        } catch (Exception e) {
            System.err.println("Cannot write test report: " + e.getMessage());
        }

        System.out.println(sb);
    }
}
