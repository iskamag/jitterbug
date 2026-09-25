package com.matepad.sumgr;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;

/** The prompt: sud starts this when a uid without a policy asks for root. */
public class RequestActivity extends Activity {
    private int uid = -1;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        try {
            uid = SuClient.firstPendingUid(SuClient.pending().text);
        } catch (IOException ignored) {
        }
        if (uid < 0) {
            finish();                       // already answered, or nothing queued
            return;
        }

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        int p = (int) (16 * getResources().getDisplayMetrics().density);
        col.setPadding(p, p, p, p);

        TextView t = new TextView(this);
        t.setTextSize(16);
        t.setText(label(uid) + "\nrequests root\n(uid " + uid + ")");
        t.setGravity(Gravity.CENTER_HORIZONTAL);
        col.addView(t);

        col.addView(button("Allow", SuClient.ALLOW, 0));
        col.addView(button("Allow for 10 minutes", SuClient.ALLOW, 10));
        col.addView(button("Deny", SuClient.DENY, 0));
        setContentView(col);
    }

    private String label(int uid) {
        PackageManager pm = getPackageManager();
        String[] pkgs = pm.getPackagesForUid(uid);
        if (pkgs != null && pkgs.length > 0) {
            try {
                ApplicationInfo ai = pm.getApplicationInfo(pkgs[0], 0);
                return String.valueOf(pm.getApplicationLabel(ai));
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }
        return "uid " + uid;
    }

    private Button button(String text, int policy, int minutes) {
        Button b = new Button(this);
        b.setText(text);
        b.setOnClickListener(v -> {
            try {
                long until = minutes > 0
                        ? System.currentTimeMillis() / 1000 + minutes * 60L : 0;
                SuClient.set(uid, policy, until);
            } catch (IOException e) {
                Toast.makeText(this, "daemon: " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
            finish();
        });
        return b;
    }
}
