package com.securitysite.securitydemosite.security.signature;

import jakarta.servlet.http.HttpServletRequest;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SignatureEngine {

    private final List<SignatureRule> rules;

    public SignatureEngine() {
        this.rules = initRules();
    }

    public List<SignatureMatch> analyze(HttpServletRequest request) {
        List<SignatureMatch> result = new ArrayList<>();

        Map<String, String> fieldsToCheck = collectFields(request);

        for (Map.Entry<String, String> entry : fieldsToCheck.entrySet()) {
            String location = entry.getKey();
            String value = entry.getValue();
            if (value == null || value.isEmpty()) {
                continue;
            }

            for (SignatureRule rule : rules) {
                Matcher m = rule.getPattern().matcher(value);
                if (m.find()) {
                    // беремо невеликий фрагмент значення для логів / UI
                    String sample = value.substring(
                            Math.max(0, m.start()),
                            Math.min(value.length(), m.end() + 20)
                    );

                    result.add(new SignatureMatch(
                            rule.getId(),
                            rule.getType(),
                            location,
                            rule.getDescription(),
                            sample
                    ));
                }
            }
        }

        return result;
    }

    /**
     * Збираємо всі текстові поля, де можуть бути атакуючі payload'и:
     * - PATH
     * - QUERY
     * - параметри (GET/POST)
     * - деякі заголовки
     */
    private Map<String, String> collectFields(HttpServletRequest request) {
        Map<String, String> map = new LinkedHashMap<>();

        String path = Optional.ofNullable(request.getRequestURI()).orElse("");
        String query = Optional.ofNullable(request.getQueryString()).orElse("");

        map.put("PATH", path);
        map.put("QUERY", query);

        // Параметри
        Enumeration<String> paramNames = request.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String name = paramNames.nextElement();
            String[] values = request.getParameterValues(name);
            if (values != null) {
                for (String v : values) {
                    map.put("PARAM:" + name, v);
                }
            }
        }

        // Деякі заголовки (можна розширити список)
        addHeaderIfPresent(request, map, "User-Agent");
        addHeaderIfPresent(request, map, "Referer");
        addHeaderIfPresent(request, map, "X-Forwarded-For");

        return map;
    }

    private void addHeaderIfPresent(HttpServletRequest request,
                                    Map<String, String> target,
                                    String headerName) {
        String value = request.getHeader(headerName);
        if (value != null && !value.isBlank()) {
            target.put("HEADER:" + headerName, value);
        }
    }

    /**
     * оголошуємо набір базових сигнатур (regex-патерни).
     */
    private List<SignatureRule> initRules() {
        List<SignatureRule> list = new ArrayList<>();

        // ------ SQL Injection (спрощені приклади) ------

        list.add(new SignatureRule(
                "SQLI_1",
                AttackType.SQL_INJECTION,
                Pattern.compile("(?i)(union\\s+all\\s+select|union\\s+select)"),
                "Підозріла конструкція UNION SELECT"
        ));

        list.add(new SignatureRule(
                "SQLI_2",
                AttackType.SQL_INJECTION,
                Pattern.compile("(?i)(or\\s+1=1|or\\s+'1'='1'|and\\s+1=1)"),
                "Проста булева SQL-інʼєкція (OR 1=1)"
        ));

        list.add(new SignatureRule(
                "SQLI_3",
                AttackType.SQL_INJECTION,
                Pattern.compile("(?i)(information_schema|pg_catalog|mysql\\.user)"),
                "Доступ до службових системних таблиць БД"
        ));

        // ------ XSS ------

        list.add(new SignatureRule(
                "XSS_1",
                AttackType.XSS,
                Pattern.compile("(?i)<script[^>]*>"),
                "Спроба вставити <script> тег"
        ));

        list.add(new SignatureRule(
                "XSS_2",
                AttackType.XSS,
                Pattern.compile("(?i)javascript:"),
                "javascript: в посиланні / параметрі"
        ));

        list.add(new SignatureRule(
                "XSS_3",
                AttackType.XSS,
                Pattern.compile("(?i)onerror\\s*=|onload\\s*="),
                "Inline-обробники подій onerror/onload"
        ));

        // ------ Path Traversal ------

        list.add(new SignatureRule(
                "PATH_1",
                AttackType.PATH_TRAVERSAL,
                Pattern.compile("\\.\\./\\.\\."),
                "Спроба виходу за межі директорії через ../.."
        ));

        list.add(new SignatureRule(
                "PATH_2",
                AttackType.PATH_TRAVERSAL,
                Pattern.compile("(?i)(etc/passwd|boot\\.ini|system32)"),
                "Доступ до чутливих системних файлів"
        ));

        // ------ Command Injection ------

        list.add(new SignatureRule(
                "CMD_1",
                AttackType.COMMAND_INJECTION,
                Pattern.compile("(;|&&|\\|\\|)\\s*(ls|cat|whoami|id|ping|curl|wget)"),
                "Можлива командна інʼєкція через оболонку ОС"
        ));

        // ------ Header Injection / CRLF ------

        list.add(new SignatureRule(
                "HDR_1",
                AttackType.HEADER_INJECTION,
                Pattern.compile("\\r\\n\\S+:"),
                "CRLF-injection у заголовках"
        ));

        // ------ Generic / OTHER ------

        list.add(new SignatureRule(
                "GEN_1",
                AttackType.OTHER,
                Pattern.compile("(?i)(<iframe|<object|<embed)"),
                "Підозрілі вбудовані HTML-обʼєкти (iframe/object/embed)"
        ));

        return Collections.unmodifiableList(list);
    }
}
