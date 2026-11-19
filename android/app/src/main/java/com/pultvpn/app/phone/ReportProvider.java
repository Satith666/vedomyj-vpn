package com.pultvpn.app.phone;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.regex.Pattern;

/**
 * Отдаёт файл отчёта «Проверки программы» другому приложению (Telegram, почта) — только на чтение,
 * только файлы из папки reports и только тому, кому его явно передали через «Отправить».
 */
public class ReportProvider extends ContentProvider {
    static final String DIR = "reports";
    private static final Pattern NAME = Pattern.compile("vedomyj-check-[0-9-]{1,40}\\.txt");

    static String authority(android.content.Context c) {
        return c.getPackageName() + ".reports";
    }

    static Uri uri(android.content.Context c, String name) {
        return Uri.parse("content://" + authority(c) + "/" + Uri.encode(name));
    }

    static final String UPDATE = "update.apk"; // скачанное и проверенное обновление — для установщика Android

    private File file(Uri uri) throws FileNotFoundException {
        String name = uri.getLastPathSegment();
        if (UPDATE.equals(name)) {
            File u = new File(new File(getContext().getFilesDir(), "update"), UPDATE);
            if (!u.isFile()) {
                throw new FileNotFoundException("no update");
            }
            return u;
        }
        if (name == null || !NAME.matcher(name).matches()) {
            throw new FileNotFoundException("no such report");
        }
        File f = new File(new File(getContext().getFilesDir(), DIR), name);
        if (!f.isFile()) {
            throw new FileNotFoundException("no such report");
        }
        return f;
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public String getType(Uri uri) {
        return UPDATE.equals(uri.getLastPathSegment()) ? "application/vnd.android.package-archive" : "text/plain";
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (mode != null && !"r".equals(mode)) {
            throw new FileNotFoundException("read only");
        }
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        File f;
        try {
            f = file(uri);
        } catch (FileNotFoundException e) {
            return null;
        }
        String[] cols = {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE};
        MatrixCursor c = new MatrixCursor(cols, 1);
        c.addRow(new Object[]{f.getName(), f.length()});
        return c;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
