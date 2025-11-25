package com.securitysite.securitydemosite.utils;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class TestUtils {

    public static MockHttpServletRequest request(String method, String path) {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setMethod(method);
        req.setRequestURI(path);
        return req;
    }

    public static MockHttpServletRequest params(MockHttpServletRequest req, String key, String value) {
        req.addParameter(key, value);
        return req;
    }

    public static MockHttpServletRequest header(MockHttpServletRequest req, String name, String value) {
        req.addHeader(name, value);
        return req;
    }

    public static MockHttpServletResponse response() {
        return new MockHttpServletResponse();
    }
}
