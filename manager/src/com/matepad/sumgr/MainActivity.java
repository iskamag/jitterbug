package com.matepad.sumgr;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The manager: pending requests, then every installed app with its policy. */
public class MainActivity extends Activity {
    private final Map<Integer, String> labels = new LinkedHashMap<>();
    private final Map<Integer, Integer> policies = new HashMap<>();
    private LinearLayout list;
    private TextView status;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setTitle("Root Manager");

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        int p = dp(10);
        col.setPadding(p, p, p, p);

        status = new TextView(this);
        status.setTextSize(13);
        col.addView(status);

        Button refresh = new Button(this);
        refresh.setText("Refresh");
        refresh.setOnClickListener(v -> refresh());
        col.addView(refresh);

        ScrollView sc = new ScrollView(this);
        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        sc.addView(list);
        col.addView(sc);
        setContentView(col);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }

    private void header(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setPadding(0, dp(12), 0, dp(4));
        list.addView(t);
    }

    private void refresh() {
        String listText, pendingText;
        try {
            listText = SuClient.list().text;
            pendingText = SuClient.pending().text;
        } catch (IOException e) {
            list.removeAllViews();
            status.setText("cannot reach the daemon at " + SuClient.SOCKET + "\n"
                    + "start it once per boot: tools/su/install.sh");
            return;
        }

        labels.clear();
        policies.clear();
        for (PackageInfo pi : getPackageManager().getInstalledPackages(0)) {
            ApplicationInfo ai = pi.applicationInfo;
            if (ai == null || labels.containsKey(ai.uid))
                continue;                       // first package wins per uid
            labels.put(ai.uid, String.valueOf(getPackageManager().getApplicationLabel(ai)));
        }
        for (String line : listText.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 2 && f[0].matches("\\d+")) {
                try {
                    policies.put(Integer.parseInt(f[0]),
                            "allow".equals(f[1]) ? SuClient.ALLOW
                                    : "deny".equals(f[1]) ? SuClient.DENY : SuClient.ASK);
                } catch (NumberFormatException ignored) {
                }
            }
        }

        List<Integer> pending = new ArrayList<>();
        for (String line : pendingText.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 1 && f[0].matches("\\d+"))
                pending.add(Integer.parseInt(f[0]));
        }

        status.setText("daemon ok · " + labels.size() + " apps · "
                + policies.size() + " policies · " + pending.size() + " pending");
        list.removeAllViews();

        if (!pending.isEmpty()) {
            header("Requests waiting");
            for (int uid : pending)
                addRow(uid, true);
        }
        header("Installed apps");
        List<Integer> uids = new ArrayList<>(labels.keySet());
        uids.sort(Comparator.comparing(u -> labels.get(u), String.CASE_INSENSITIVE_ORDER));
        for (int uid : uids)
            addRow(uid, false);
    }

    private void addRow(int uid, boolean pending) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(4), 0, dp(4));

        String label = labels.getOrDefault(uid, "uid " + uid);
        TextView tv = new TextView(this);
        tv.setText(label + "\n" + (pending ? "REQUESTING ROOT · " : "") + "uid " + uid);
        tv.setTextSize(13);
        tv.setLayoutParams(new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(tv);

        int pol = policies.containsKey(uid) ? policies.get(uid) : SuClient.ASK;
        Button btn = new Button(this);
        btn.setText(SuClient.policyName(pol));
        btn.setOnClickListener(v -> cycle(uid));
        row.addView(btn);
        list.addView(row);
    }

    /** allow -> ask -> deny -> allow */
    private void cycle(int uid) {
        int now = policies.containsKey(uid) ? policies.get(uid) : SuClient.ASK;
        int next = now == SuClient.ALLOW ? SuClient.ASK
                : now == SuClient.ASK ? SuClient.DENY : SuClient.ALLOW;
        try {
            SuClient.set(uid, next, 0);
            policies.put(uid, next);
        } catch (IOException e) {
            status.setText("cannot reach the daemon: " + e.getMessage());
            return;
        }
        refresh();
    }
}
