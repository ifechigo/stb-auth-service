package com.suntrustbank.auth.core.configs.cache;

public interface ICacheService {
    void save(String key, String value);

    String get(String key);

    void remove(String key);

    void empty();
}
