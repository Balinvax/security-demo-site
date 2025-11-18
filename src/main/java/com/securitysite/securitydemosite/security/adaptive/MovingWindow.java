package com.securitysite.securitydemosite.security.adaptive;

import java.util.LinkedList;

public class MovingWindow<T> {

    private final int maxSize;
    private final LinkedList<T> list = new LinkedList<>();

    public MovingWindow(int maxSize) {
        this.maxSize = maxSize;
    }

    public synchronized void add(T item) {
        list.addLast(item);
        if (list.size() > maxSize) {
            list.removeFirst();
        }
    }

    public synchronized LinkedList<T> snapshot() {
        return new LinkedList<>(list);
    }

    public int size() {
        return list.size();
    }
}
