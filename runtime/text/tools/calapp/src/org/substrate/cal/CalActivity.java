package org.substrate.cal;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.view.View;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Calibration probe for andro-substrate runtime/text.
 *
 * Reads a case list produced by the Rust harness (so the two sides measure
 * byte-identical inputs) and writes one JSON object per case with the values
 * android.graphics.Paint actually returns on this device.
 *
 * Nothing here is a reimplementation. Every number is the framework's.
 */
public class CalActivity extends Activity {

    private String mLocaleTag;

    @Override
    protected void attachBaseContext(Context base) {
        mLocaleTag = null;
        Intent i = getIntent();
        if (i != null && i.getStringExtra("locale") != null) {
            mLocaleTag = i.getStringExtra("locale");
        }
        if (mLocaleTag != null && !mLocaleTag.isEmpty()) {
            Locale l = Locale.forLanguageTag(mLocaleTag);
            Locale.setDefault(l);
            Configuration c = new Configuration(base.getResources().getConfiguration());
            c.setLocale(l);
            c.setLayoutDirection(l);
            base = base.createConfigurationContext(c);
        }
        super.attachBaseContext(base);
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        try {
            run();
        } catch (Throwable t) {
            try {
                File out = outFile();
                Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8);
                w.write("{\"fatal\":" + quote(String.valueOf(t)) + "}\n");
                w.close();
            } catch (Throwable ignored) {
            }
        }
        finish();
    }

    private File outFile() {
        File dir = getFilesDir();
        return new File(dir, mLocaleTag == null || mLocaleTag.isEmpty()
                ? "device.jsonl" : ("device-" + mLocaleTag + ".jsonl"));
    }

    private void run() throws Exception {
        File dir = getFilesDir();
        File in = new File(dir, "cases.jsonl");

        DisplayMetrics dm = getResources().getDisplayMetrics();
        StringBuilder header = new StringBuilder();
        header.append("{\"record\":\"device\"");
        header.append(",\"sdk\":" + android.os.Build.VERSION.SDK_INT);
        header.append(",\"release\":").append(quote(android.os.Build.VERSION.RELEASE));
        header.append(",\"fingerprint\":").append(quote(android.os.Build.FINGERPRINT));
        header.append(",\"model\":").append(quote(android.os.Build.MODEL));
        header.append(",\"density\":" + dm.density);
        header.append(",\"density_dpi\":" + dm.densityDpi);
        header.append(",\"locale\":").append(quote(Locale.getDefault().toLanguageTag()));
        header.append(",\"font_scale\":" + getResources().getConfiguration().fontScale);
        header.append("}\n");

        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream(in), StandardCharsets.UTF_8));
             Writer w = new OutputStreamWriter(new FileOutputStream(outFile()), StandardCharsets.UTF_8)) {
            w.write(header.toString());
            String line;
            while ((line = r.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                JSONObject o = new JSONObject(line);
                String kind = o.optString("kind", "measure");
                String rec;
                if (kind.equals("ellipsize")) {
                    rec = doEllipsize(o);
                } else if (kind.equals("layout")) {
                    rec = doLayout(o);
                } else {
                    rec = doMeasure(o);
                }
                w.write(rec);
                w.write("\n");
            }
        }
    }

    // ---- measure -------------------------------------------------------

    private String doMeasure(JSONObject o) throws Exception {
        String text = o.getString("text");
        float size = (float) o.getDouble("size_px");
        float ls = (float) o.optDouble("letter_spacing_px", 0.0);
        float sx = (float) o.optDouble("text_scale_x", 1.0);
        boolean bold = o.optBoolean("bold", false);
        String tfn = o.optString("typeface", "default");

        Paint p = buildPaint(size, tfn, bold, ls, sx);

        float w = p.measureText(text);
        float[] widths = new float[text.length()];
        p.getTextWidths(text, widths);
        Paint.FontMetrics fm = p.getFontMetrics();
        Paint.FontMetricsInt fmi = p.getFontMetricsInt();

        StringBuilder sb = new StringBuilder();
        sb.append("{\"id\":").append(o.getInt("id"));
        sb.append(",\"kind\":\"measure\"");
        sb.append(",\"width\":").append(w);
        sb.append(",\"widths\":[");
        for (int i = 0; i < widths.length; i++) {
            if (i > 0) sb.append(",");
            sb.append(widths[i]);
        }
        sb.append("]");
        sb.append(",\"ascent\":").append(fm.ascent);
        sb.append(",\"descent\":").append(fm.descent);
        sb.append(",\"top\":").append(fm.top);
        sb.append(",\"bottom\":").append(fm.bottom);
        sb.append(",\"leading\":").append(fm.leading);
        sb.append(",\"ascent_int\":").append(fmi.ascent);
        sb.append(",\"descent_int\":").append(fmi.descent);
        sb.append(",\"top_int\":").append(fmi.top);
        sb.append(",\"bottom_int\":").append(fmi.bottom);
        // Sum of per-character advances: exposes context-dependent shaping and
        // letter-spacing interaction that measureText folds in.
        float sum = 0f;
        for (float x : widths) sum += x;
        sb.append(",\"char_sum\":").append(sum);
        sb.append(",\"measure_minus_charsum\":").append(w - sum);
        sb.append("}");
        return sb.toString();
    }

    // ---- ellipsize -----------------------------------------------------

    private String doEllipsize(JSONObject o) throws Exception {
        String text = o.getString("text");
        float size = (float) o.getDouble("size_px");
        float avail = (float) o.getDouble("avail_px");
        String where = o.optString("where", "END");
        String tfn = o.optString("typeface", "default");
        boolean bold = o.optBoolean("bold", false);

        TextPaint p = new TextPaint(buildPaint(size, tfn, bold,
                (float) o.optDouble("letter_spacing_px", 0.0),
                (float) o.optDouble("text_scale_x", 1.0)));

        TextUtils.TruncateAt at;
        if (where.equals("START")) at = TextUtils.TruncateAt.START;
        else if (where.equals("MIDDLE")) at = TextUtils.TruncateAt.MIDDLE;
        else at = TextUtils.TruncateAt.END;

        CharSequence r = TextUtils.ellipsize(text, p, avail, at);
        StringBuilder sb = new StringBuilder();
        sb.append("{\"id\":").append(o.getInt("id"));
        sb.append(",\"kind\":\"ellipsize\"");
        sb.append(",\"result\":").append(quote(r == null ? "" : r.toString()));
        sb.append(",\"result_width\":").append(p.measureText(r == null ? "" : r.toString()));
        sb.append("}");
        return sb.toString();
    }

    // ---- paragraph layout ---------------------------------------------

    private String doLayout(JSONObject o) throws Exception {
        String text = o.getString("text");
        float size = (float) o.getDouble("size_px");
        int widthPx = (int) o.getInt("width_px");
        String tfn = o.optString("typeface", "default");
        boolean bold = o.optBoolean("bold", false);

        Paint p = buildPaint(size, tfn, bold,
                (float) o.optDouble("letter_spacing_px", 0.0),
                (float) o.optDouble("text_scale_x", 1.0));
        TextPaint tp = new TextPaint(p);
        StaticLayout.Builder b = StaticLayout.Builder.obtain(text, 0, text.length(), tp, widthPx);
        b.setAlignment(Layout.Alignment.ALIGN_NORMAL);
        b.setIncludePad(true);
        b.setLineSpacing(0f, 1f);
        StaticLayout sl = b.build();

        StringBuilder sb = new StringBuilder();
        sb.append("{\"id\":").append(o.getInt("id"));
        sb.append(",\"kind\":\"layout\"");
        sb.append(",\"lines\":").append(sl.getLineCount());
        sb.append(",\"height\":").append(sl.getHeight());
        sb.append(",\"line_count_minus\":");
        // Per-line measured widths, for per-line error attribution.
        sb.append("[");
        for (int i = 0; i < sl.getLineCount(); i++) {
            if (i > 0) sb.append(",");
            sb.append(sl.getLineWidth(i));
        }
        sb.append("]");
        sb.append("}");
        return sb.toString();
    }

    // ---- paint ---------------------------------------------------------

    private Paint buildPaint(float size, String tfn, boolean bold, float ls, float sx) {
        Paint p = new Paint();
        p.setAntiAlias(false);
        p.setSubpixelText(false);
        p.setDither(false);
        p.setLinearText(false);
        p.setTextSize(size);
        if (sx != 1.0f) p.setTextScaleX(sx);
        if (ls != 0.0f) p.setLetterSpacing(ls / size);
        Typeface tf = Typeface.create(tfn, bold ? Typeface.BOLD : Typeface.NORMAL);
        p.setTypeface(tf);
        return p;
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
