package ru.iriyc.cstorage.entity;

public enum EnterprisePlan {
    FREE(20 * 1024 * 1024, 0);

    EnterprisePlan(int maxDiskSpaceUsage, int price) {
        this.maxDiskSpaceUsage = maxDiskSpaceUsage;
        this.price = price;
    }

    private final int maxDiskSpaceUsage;
    private final int price;
}
