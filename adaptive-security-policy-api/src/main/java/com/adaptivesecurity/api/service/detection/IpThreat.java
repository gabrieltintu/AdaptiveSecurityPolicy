package com.adaptivesecurity.api.service.detection;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class IpThreat {

    private int totalCount;
    private final Set<String> categories = new LinkedHashSet<>();

    public void addSignal(String category, int count) {
        totalCount += count;
        categories.add(category);
    }

    public int totalCount() {
        return totalCount;
    }

    public List<String> categories() {
        return new ArrayList<>(categories);
    }
}
