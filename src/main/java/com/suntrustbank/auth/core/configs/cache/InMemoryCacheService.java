package com.suntrustbank.auth.core.configs.cache;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import java.util.concurrent.TimeUnit;

public class InMemoryCacheService implements ICacheService {

    private final Cache<String, String> cache;

    public InMemoryCacheService(int expiryDuration, TimeUnit timeUnit) {
        cache = CacheBuilder.newBuilder()
                .expireAfterWrite(expiryDuration, timeUnit)
                .build();
    }

    @Override
    public void remove(String key) {
        cache.invalidate(key);
    }
    @Override
    public String get(String key) {
        return cache.getIfPresent(key);
    }

    @Override
    public void save(String key, String value) {
        cache.put(key, value);
    }

    @Override
    public void empty() {
        cache.invalidateAll();
        cache.cleanUp();
    }
}

