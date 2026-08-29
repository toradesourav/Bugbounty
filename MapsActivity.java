package com.example.myvulnlab;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class MapsActivity extends AppCompatActivity {

    // NOTE: this is a fake, non-functional placeholder key for a
    // deliberate security-education demo. Never hardcode real API
    // keys in source — use environment variables / a secrets
    // manager / gradle.properties excluded from git instead.
    private static final String API_KEY = "AIzaSyTEST-KEY-FOR-PRACTICE-123456";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_maps);
        // initMap(API_KEY);
    }
}
