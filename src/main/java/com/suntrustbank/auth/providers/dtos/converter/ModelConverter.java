package com.suntrustbank.auth.providers.dtos.converter;

import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;

import java.lang.reflect.Type;
import java.util.Map;

public class ModelConverter {
    public static String mapToJsonConverter(Map<String, Object> data) {
        Gson gson = new Gson();
        return gson.toJson(data);
    }

    public static Map<String, Object> jsonToMapConverter(String data) {
        Gson gson = new Gson();
        Type type = new TypeToken<Map<String, Object>>() {
        }.getType();
        return gson.fromJson(data, type);
    }
}
