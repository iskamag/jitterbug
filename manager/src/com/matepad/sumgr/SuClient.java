package com.matepad.sumgr;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** The sud protocol, from the app side: see tools/su/proto.h. */
final class SuClient {
    // The daemon's socket.  build.sh substitutes this line with SU_DIR from
    // the environment, so the app and sud agree on the toolbox directory;
    // the default matches su/config.c.
    static final String SOCKET = "/data/local/tmp/su.sock";
    private static final int MAGIC = 0x53554431;

    static final int OP_LIST = 2, OP_SET = 3, OP_PENDING = 4, OP_LOG = 5;
    static final int DENY = 0, ALLOW = 1, ASK = 2;

    static final class Reply {
        int rc;
        String text = "";
    }

    private SuClient() {}

    private static byte[] readN(DataInputStream in, int n) throws IOException {
        byte[] b = new byte[n];
        in.readFully(b);
        return b;
    }

    private static Reply call(int op, int uid, int policy, long until) throws IOException {
        LocalSocket s = new LocalSocket();
        try {
            s.connect(new LocalSocketAddress(SOCKET, LocalSocketAddress.Namespace.FILESYSTEM));
            // struct su_req: u32 magic, op, uid, policy; i64 until; u32 len; +4 pad
            ByteBuffer b = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
            b.putInt(MAGIC).putInt(op).putInt(uid).putInt(policy).putLong(until).putInt(0).putInt(0);
            OutputStream out = s.getOutputStream();
            out.write(b.array());
            out.flush();

            DataInputStream in = new DataInputStream(s.getInputStream());
            ByteBuffer h = ByteBuffer.wrap(readN(in, 8)).order(ByteOrder.LITTLE_ENDIAN);
            Reply r = new Reply();
            r.rc = h.getInt();
            int len = h.getInt();
            if (len > 0)
                r.text = new String(readN(in, len), StandardCharsets.UTF_8);
            return r;
        } finally {
            try {
                s.close();
            } catch (IOException ignored) {
            }
        }
    }

    static Reply list() throws IOException {
        return call(OP_LIST, 0, 0, 0);
    }

    static Reply pending() throws IOException {
        return call(OP_PENDING, 0, 0, 0);
    }

    static Reply set(int uid, int policy, long until) throws IOException {
        return call(OP_SET, uid, policy, until);
    }

    /** uid -> policy, parsed from the daemon's LIST reply */
    static int policyOf(String listText, int uid) {
        for (String line : listText.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 2) {
                try {
                    if (Integer.parseInt(f[0]) == uid)
                        return "allow".equals(f[1]) ? ALLOW : "deny".equals(f[1]) ? DENY : ASK;
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return ASK;
    }

    static String policyName(int p) {
        return p == ALLOW ? "allow" : p == DENY ? "deny" : "ask";
    }

    static int firstPendingUid(String pendingText) {
        for (String line : pendingText.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 1) {
                try {
                    return Integer.parseInt(f[0]);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return -1;
    }
}
