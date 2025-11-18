package com.securitysite.securitydemosite.security.rules;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class RuleParser {

    public List<CompiledRule> loadFromResource(String path) {
        List<CompiledRule> rules = new ArrayList<>();

        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(
                        Objects.requireNonNull(
                                this.getClass().getClassLoader().getResourceAsStream(path)
                        )
                )
        )) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();

                if (line.isEmpty() || line.startsWith("#")) continue;
                if (!line.startsWith("RULE")) continue;

                CompiledRule rule = parseRule(line);
                rules.add(rule);
            }

        } catch (Exception e) {
            throw new RuntimeException("Cannot load DSL rules", e);
        }

        return rules;
    }

    /**
     * Парсинг правил із багаторядкового тексту (для config’а).
     */
    public RuleEngine parse(String text) {
        List<CompiledRule> rules = new ArrayList<>();
        if (text == null) {
            return new RuleEngine(rules);
        }

        String[] lines = text.split("\\R");
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (!line.startsWith("RULE")) continue;

            rules.add(parseRule(line));
        }

        return new RuleEngine(rules);
    }

    // RULE BLOCK_XSS IF param CONTAINS "<script"
    private CompiledRule parseRule(String line) {
        if (!line.contains(" IF ")) {
            throw new RuntimeException("Invalid rule syntax: " + line);
        }

        String[] parts = line.split(" IF ");
        String name = parts[0].replace("RULE", "").trim();
        String condition = parts[1].trim();

        return new CompiledRule(name, condition);
    }
}
