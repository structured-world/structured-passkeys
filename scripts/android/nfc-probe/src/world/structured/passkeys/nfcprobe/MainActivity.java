package world.structured.passkeys.nfcprobe;

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Log;
import android.view.WindowManager;
import android.widget.TextView;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * The FIDO applet of CTAP 2.2 §11.3 on a device held to the phone. Every tap runs the steps named
 * by the "steps" extra (all of them by default) and logs each APDU, its answer and a verdict under
 * the log tag "NfcProbe", where scripts/android/nfc-probe.sh reads them.
 */
public class MainActivity extends Activity implements NfcAdapter.ReaderCallback {
    private static final String TAG = "NfcProbe";
    private static final byte[] SELECT = hex("00A4040008A0000006472F000100");
    /** How long the waiting step keeps the device in the field before it asks, past the two
     * minutes a tap counts as user presence. */
    private static final long TAP_EXPIRY_MS = 125_000;

    private List<String> steps = Arrays.asList("select", "info", "selection", "chain", "wait");
    private TextView view;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        view = new TextView(this);
        view.setTextSize(18);
        // Colors of its own: the default theme can give light text on a light background.
        view.setTextColor(0xFF000000);
        view.setBackgroundColor(0xFFFFFFFF);
        view.setPadding(32, 32, 32, 32);
        setContentView(view);
        String named = getIntent().getStringExtra("steps");
        if (named != null) {
            steps = Arrays.asList(named.split(","));
        }
        show("Hold the device to the phone. Steps: " + steps);
    }

    @Override
    protected void onResume() {
        super.onResume();
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter == null || !adapter.isEnabled()) {
            show("NFC is off or missing");
            return;
        }
        Bundle extras = new Bundle();
        // A presence check every few seconds rather than the default 125 ms, so the long wait of
        // a screen is not interrupted by the reader polling the card.
        extras.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 5000);
        adapter.enableReaderMode(
                this,
                this,
                NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                extras);
    }

    @Override
    protected void onPause() {
        super.onPause();
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter != null) {
            adapter.disableReaderMode(this);
        }
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        IsoDep card = IsoDep.get(tag);
        if (card == null) {
            log("tag without ISO-DEP: " + Arrays.toString(tag.getTechList()));
            return;
        }
        log("tap: uid " + toHex(tag.getId()) + ", extended APDUs "
                + card.isExtendedLengthApduSupported() + ", max transceive "
                + card.getMaxTransceiveLength());
        try {
            card.connect();
            card.setTimeout(35_000);
            for (String step : steps) {
                run(card, step.trim());
            }
            log("done");
        } catch (IOException | InterruptedException error) {
            log("I/O failure: " + error);
        } finally {
            try {
                card.close();
            } catch (IOException ignored) {
                // The card is gone: nothing left to close.
            }
        }
    }

    private void run(IsoDep card, String step) throws IOException, InterruptedException {
        log("== " + step);
        switch (step) {
            case "select":
                expect(send(card, SELECT), "4649444F5F325F309000", "SELECT answers FIDO_2_0");
                break;
            case "info": {
                byte[] info = send(card, hex("80100000010400"));
                verdict(endsWith(info, 0x90, 0x00) && contains(info, hex("636E6663")),
                        "getInfo lists nfc");
                if (card.isExtendedLengthApduSupported()) {
                    byte[] extended = send(card, hex("8010000000000104"));
                    verdict(Arrays.equals(info, extended), "getInfo in an extended APDU");
                }
                break;
            }
            case "selection":
                expect(send(card, hex("80100000010B00")), "009000",
                        "selection: the tap is presence, no screen");
                break;
            case "chain": {
                // getPINRetries, 06 A2 01 02 02 01 ({1: 2, 2: 1}), in two parts: CLA 90 for the
                // first, CLA 80 with Le for the last (§11.3.6).
                expect(send(card, hex("901000000306A201")), "9000",
                        "chain: the first part is taken");
                byte[] retries = send(card, hex("801000000302020100"));
                verdict(endsWith(retries, 0x90, 0x00) && retries[0] == 0,
                        "chain: getPINRetries answers");
                break;
            }
            case "wait":
                waitForUser(card);
                break;
            default:
                log("unknown step " + step);
        }
    }

    /** authenticatorSelection once the tap no longer counts: the device shows its screen and the
     * reader polls with NFCCTAP_GETRESPONSE until the person answers on the device. */
    private void waitForUser(IsoDep card) throws IOException, InterruptedException {
        long started = System.currentTimeMillis();
        while (System.currentTimeMillis() - started < TAP_EXPIRY_MS) {
            show("Keep the device on the phone: "
                    + (TAP_EXPIRY_MS - (System.currentTimeMillis() - started)) / 1000 + " s");
            Thread.sleep(1000);
        }
        byte[] answer = send(card, hex("80108000010B00"));
        verdict(Arrays.equals(answer, hex("029100")), "wait: status update, user presence needed");
        log("ANSWER ON THE DEVICE NOW");
        show("Answer the screen on the device");
        int updates = 0;
        while (endsWith(answer, 0x91, 0x00)) {
            Thread.sleep(100);
            answer = card.transceive(hex("8011000000"));
            updates++;
        }
        log("< " + toHex(answer) + " after " + updates + " polls");
        verdict(endsWith(answer, 0x90, 0x00), "wait: the answer after the polls");
    }

    private byte[] send(IsoDep card, byte[] apdu) throws IOException {
        log("> " + toHex(apdu));
        byte[] answer = card.transceive(apdu);
        log("< " + toHex(answer));
        return answer;
    }

    private void expect(byte[] answer, String expected, String what) {
        verdict(Arrays.equals(answer, hex(expected)), what);
    }

    private void verdict(boolean ok, String what) {
        log((ok ? "ok: " : "FAILED: ") + what);
    }

    private static boolean endsWith(byte[] data, int sw1, int sw2) {
        return data.length >= 2
                && (data[data.length - 2] & 0xFF) == sw1
                && (data[data.length - 1] & 0xFF) == sw2;
    }

    private static boolean contains(byte[] data, byte[] part) {
        outer:
        for (int at = 0; at + part.length <= data.length; at++) {
            for (int i = 0; i < part.length; i++) {
                if (data[at + i] != part[i]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private void log(String line) {
        Log.i(TAG, line);
        show(line);
    }

    private void show(String line) {
        runOnUiThread(() -> view.setText(line));
    }

    private static byte[] hex(String text) {
        byte[] bytes = new byte[text.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte b : bytes) {
            text.append(String.format("%02X", b));
        }
        return text.toString();
    }
}
