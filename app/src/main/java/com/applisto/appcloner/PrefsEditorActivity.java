package com.applisto.appcloner;

import android.app.AlertDialog;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.*;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import java.util.*;

public class PrefsEditorActivity extends AppCompatActivity {
    private static final String TAG = "PrefsEditorActivity";

    private String targetPackage;
    private String authority;
    private Spinner filesSpinner;
    private ListView listView;
    private ArrayAdapter<String> keysAdapter;
    private final Map<String, Object> currentPrefs = new LinkedHashMap<>();
    private String currentFile;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("Edit Shared Preferences");
        title.setTextSize(18);
        root.addView(title);

        filesSpinner = new Spinner(this);
        root.addView(filesSpinner);

        listView = new ListView(this);
        root.addView(listView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        Button addBtn = new Button(this);
        addBtn.setText("Add Key");
        root.addView(addBtn);

        setContentView(root);

        targetPackage = getIntent().getStringExtra("pkg");
        String appName = getIntent().getStringExtra("appName");
        if (targetPackage == null || targetPackage.trim().isEmpty()) {
            Toast.makeText(this, "No target package.", Toast.LENGTH_LONG).show();
            finish();
            return;
        }
        authority = targetPackage + ".com.applisto.appcloner.DefaultProvider";
        setTitle(appName != null ? ("Prefs: " + appName) : "Preference Editor");

        keysAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_2, android.R.id.text1, new ArrayList<>()) {
            @Override
            public android.view.View getView(int position, android.view.View convertView, android.view.ViewGroup parent) {
                android.view.View view = super.getView(position, convertView, parent);
                TextView text1 = view.findViewById(android.R.id.text1);
                TextView text2 = view.findViewById(android.R.id.text2);
                String full = getItem(position);
                String key = full;
                String val = "";
                if (full != null) {
                    String[] parts = full.split("\n", 2);
                    key = parts[0];
                    // FIXED: Correctly access the second part of the split array
                    if (parts.length > 1) val = parts[1];
                }
                text1.setText(key);
                text2.setText(val);
                return view;
            }
        };
        listView.setAdapter(keysAdapter);

        filesSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, android.view.View view, int position, long id) {
                String file = (String) parent.getItemAtPosition(position);
                if (!file.equals(currentFile)) {
                    currentFile = file;
                    loadPrefs(file);
                }
            }
            @Override public void onNothingSelected(AdapterView<?> parent) {}
        });

        listView.setOnItemClickListener((parent, view, position, id) -> {
            String combined = keysAdapter.getItem(position);
            if (combined == null) return;
            String key = combined.split("\n", 2)[0];
            Object val = currentPrefs.get(key);
            showEditDialog(key, val);
        });

        listView.setOnItemLongClickListener((parent, view, position, id) -> {
            String combined = keysAdapter.getItem(position);
            if (combined == null) return true;
            String key = combined.split("\n", 2)[0];
            new AlertDialog.Builder(this)
                    .setTitle("Delete Key")
                    .setMessage("Delete '" + key + "'?")
                    .setPositiveButton("Delete", (d, w) -> {
                        if (removePref(currentFile, key)) {
                            loadPrefs(currentFile);
                        } else {
                            Toast.makeText(this, "Delete failed", Toast.LENGTH_SHORT).show();
                        }
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
            return true;
        });

        addBtn.setOnClickListener(v -> showEditDialog(null, null));

        loadFiles();
    }

    private Uri providerUri() {
        return Uri.parse("content://" + authority);
    }

    private void loadFiles() {
        new Thread(() -> {
            try {
                Bundle res = getContentResolver().call(providerUri(), "list_prefs", null, null);
                ArrayList<String> files = (res != null) ? res.getStringArrayList("files") : null;
                if (files == null) files = new ArrayList<>();
                ArrayList<String> finalFiles = files;
                runOnUiThread(() -> {
                    ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, finalFiles);
                    adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
                    filesSpinner.setAdapter(adapter);
                    if (!finalFiles.isEmpty()) filesSpinner.setSelection(0);
                    if (finalFiles.isEmpty()) {
                        keysAdapter.clear();
                        keysAdapter.notifyDataSetChanged();
                        Toast.makeText(this, "No SharedPreferences found.", Toast.LENGTH_SHORT).show();
                    }
                });
            } catch (Throwable t) {
                Log.e(TAG, "loadFiles error", t);
                runOnUiThread(() -> Toast.makeText(this, "Failed to query provider. Is the app cloned?", Toast.LENGTH_LONG).show());
            }
        }).start();
    }

    private void loadPrefs(String file) {
        new Thread(() -> {
            currentPrefs.clear();
            try {
                Bundle res = getContentResolver().call(providerUri(), "get_prefs", file, null);
                if (res != null) {
                    for (String k : res.keySet()) {
                        currentPrefs.put(k, res.get(k));
                    }
                }
                List<String> keys = new ArrayList<>(currentPrefs.keySet());
                Collections.sort(keys, String.CASE_INSENSITIVE_ORDER);
                runOnUiThread(() -> {
                    keysAdapter.clear();
                    for (String k : keys) {
                        Object v = currentPrefs.get(k);
                        String type = (v != null) ? v.getClass().getSimpleName() : "null";
                        String disp = String.valueOf(v);
                        if (disp.length() > 100) disp = disp.substring(0, 97) + "...";
                        keysAdapter.add(k + "\n(" + type + ") " + disp);
                    }
                    keysAdapter.notifyDataSetChanged();
                    setTitle("Editing: " + file + " (" + targetPackage + ")");
                });
            } catch (Throwable t) {
                Log.e(TAG, "loadPrefs error", t);
                runOnUiThread(() -> Toast.makeText(this, "Failed to load prefs", Toast.LENGTH_LONG).show());
            }
        }).start();
    }

    private void showEditDialog(@Nullable String key, @Nullable Object currentValue) {
        boolean isEdit = key != null;

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);

        EditText keyEt = new EditText(this);
        keyEt.setHint("Key");
        if (isEdit) {
            keyEt.setText(key);
            keyEt.setEnabled(false);
        }
        layout.addView(keyEt);

        Spinner typeSpinner = new Spinner(this);
        ArrayAdapter<String> typeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item,
                Arrays.asList("String", "Integer", "Long", "Boolean", "Float"));
        typeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        typeSpinner.setAdapter(typeAdapter);
        layout.addView(typeSpinner);

        EditText valueEt = new EditText(this);
        valueEt.setHint("Value");
        layout.addView(valueEt);

        if (currentValue != null) {
            if (currentValue instanceof Boolean) typeSpinner.setSelection(3);
            else if (currentValue instanceof Integer) typeSpinner.setSelection(1);
            else if (currentValue instanceof Long) typeSpinner.setSelection(2);
            else if (currentValue instanceof Float) typeSpinner.setSelection(4);
            else typeSpinner.setSelection(0);
            valueEt.setText(String.valueOf(currentValue));
        }

        new AlertDialog.Builder(this)
                .setTitle(isEdit ? "Edit Value" : "Add Key")
                .setView(layout)
                .setPositiveButton(isEdit ? "Save" : "Add", (d, w) -> {
                    String k = keyEt.getText().toString().trim();
                    String type = (String) typeSpinner.getSelectedItem();
                    String val = valueEt.getText().toString();
                    if (k.isEmpty()) {
                        Toast.makeText(this, "Key is required", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    if (putPref(currentFile, k, type, val)) {
                        loadPrefs(currentFile);
                    } else {
                        Toast.makeText(this, "Update failed", Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private boolean putPref(String file, String key, String type, String value) {
        try {
            Bundle extras = new Bundle();
            extras.putString("type", type);
            switch (type) {
                case "Integer":
                    extras.putInt("value", Integer.parseInt(value));
                    break;
                case "Long":
                    extras.putLong("value", Long.parseLong(value));
                    break;
                case "Boolean":
                    extras.putBoolean("value", Boolean.parseBoolean(value));
                    break;
                case "Float":
                    extras.putFloat("value", Float.parseFloat(value));
                    break;
                default:
                    extras.putString("value", value);
            }
            Bundle res = getContentResolver().call(providerUri(), "put_pref", file + ":" + key, extras);
            return res != null && res.getBoolean("ok", false);
        } catch (Throwable t) {
            Log.e(TAG, "putPref error", t);
            return false;
        }
    }

    private boolean removePref(String file, String key) {
        try {
            Bundle res = getContentResolver().call(providerUri(), "remove_pref", file + ":" + key, null);
            return res != null && res.getBoolean("ok", false);
        } catch (Throwable t) {
            Log.e(TAG, "removePref error", t);
            return false;
        }
    }

    // FIXED: Correctly initialize the byte array with size 6
    private String randomMac() {
        // Generate a random MAC address (6 bytes)
        byte[] macAddress = new byte[6]; // Standard MAC address length
        new Random().nextBytes(macAddress);

        // Set the locally administered bit and unicast bit
        macAddress[0] = (byte) ((macAddress[0] & (byte) 252) | (byte) 2);

        // Format as a string (e.g., 01:23:45:67:89:ab)
        StringBuilder sb = new StringBuilder(18);
        for (int i = 0; i < macAddress.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", macAddress[i] & 0xFF));
        }
        return sb.toString();
    }
}
