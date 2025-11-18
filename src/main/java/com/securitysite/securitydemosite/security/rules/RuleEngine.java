package com.securitysite.securitydemosite.security.ruledsl;

import jakarta.servlet.http.HttpServletRequest;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RuleEngine {

    private final List<CompiledRule> rules;

    public RuleEngine(List<CompiledRule> rules) {
        this.rules = rules;
    }

    public List<String> evaluate(HttpServletRequest request, Map<String, Object> context) {

        List<String> triggered = new ArrayList<>();

        for (CompiledRule r : rules) {
            if (evaluateCondition(r.getCondition(), request, context)) {
                triggered.add(r.getName());
            }
        }

        return triggered;
    }

    private boolean evaluateCondition(String cond,
                                      HttpServletRequest req,
                                      Map<String, Object> ctx) {

        cond = cond.trim();

        // Підтримуємо:
        // - CONTAINS
        // - MATCHES /regex/
        // - IN [..]
        // - порівняння
        // - role, method, ip, path, param

        // ============================
        // 1) CONTAINS
        // ============================
        if (cond.contains(" CONTAINS ")) {
            String[] parts = cond.split(" CONTAINS ");
            String field = resolveField(parts[0].trim(), req, ctx);
            String val = unquote(parts[1].trim());
            return field != null && field.contains(val);
        }

        // ============================
        // 2) MATCHES /.../
        // ============================
        if (cond.contains(" MATCHES ")) {
            String[] parts = cond.split(" MATCHES ");
            String field = resolveField(parts[0].trim(), req, ctx);
            String regex = parts[1].trim();

            if (regex.startsWith("/") && regex.endsWith("/")) {
                regex = regex.substring(1, regex.length() - 1);
            }
            return field != null && field.matches(regex);
        }

        // ============================
        // 3) NOT IN [...]
        // ============================
        if (cond.contains(" NOT IN ")) {
            String[] parts = cond.split(" NOT IN ");
            String fieldVal = resolveField(parts[0].trim(), req, ctx);
            Set<String> list = parseList(parts[1]);
            return fieldVal != null && !list.contains(fieldVal);
        }

        // ============================
        // 4) IN [...]
        // ============================
        if (cond.contains(" IN ")) {
            String[] parts = cond.split(" IN ");
            String fieldVal = resolveField(parts[0].trim(), req, ctx);
            Set<String> list = parseList(parts[1]);
            return fieldVal != null && list.contains(fieldVal);
        }

        // ============================
        // 5) role != "ADMIN"
        // ============================
        if (cond.contains("!=")) {
            String[] parts = cond.split("!=");
            String left = resolveField(parts[0].trim(), req, ctx);
            String right = unquote(parts[1].trim());
            return !Objects.equals(left, right);
        }

        // ============================
        // 6) >, <, >=, <=
        // ============================
        if (cond.contains(">")) {
            String[] parts = cond.split(">");
            double left = parseDouble(resolveField(parts[0].trim(), req, ctx));
            double right = Double.parseDouble(parts[1].trim());
            return left > right;
        }

        return false; // якщо не впізнали правило
    }


    private String resolveField(String token, HttpServletRequest req, Map<String, Object> ctx) {

        if (token.equals("path")) return req.getRequestURI();
        if (token.equals("method")) return req.getMethod();
        if (token.equals("query")) return req.getQueryString();
        if (token.equals("role")) return (String) ctx.get("role");
        if (token.equals("param")) return req.getQueryString(); // спрощено
        if (token.equals("any")) return req.getRequestURI() + " " + req.getQueryString();
        if (token.startsWith("header.")) {
            String h = token.substring("header.".length());
            return req.getHeader(h);
        }
        if (token.startsWith("ip.")) {
            return String.valueOf(ctx.get(token));
        }

        return null;
    }

    private String unquote(String s) {
        if (s.startsWith("\"") && s.endsWith("\""))
            return s.substring(1, s.length() - 1);
        return s;
    }

    private Set<String> parseList(String s) {
        s = s.trim();
        if (!s.startsWith("[") || !s.endsWith("]")) return Set.of();
        s = s.substring(1, s.length() - 1);
        String[] arr = s.split(",");
        Set<String> set = new HashSet<>();
        for (String a : arr) set.add(unquote(a.trim()));
        return set;
    }
}
