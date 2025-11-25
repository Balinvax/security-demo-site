package com.securitysite.securitydemosite.utils;

import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;

public class IteratorEnumeration<T> implements Enumeration<T> {

    private final Iterator<T> it;

    @SafeVarargs
    public IteratorEnumeration(T... values) {
        this.it = Arrays.asList(values).iterator();
    }

    @Override
    public boolean hasMoreElements() {
        return it.hasNext();
    }

    @Override
    public T nextElement() {
        return it.next();
    }
}
