package app.securevault.feature.recovery

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import app.securevault.core.vault.VaultMetadata
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import org.json.JSONObject
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The printable emergency recovery kit.
 *
 * What goes on the sheet: the parameters a future version of this app -- or a forensic
 * reimplementation of the format -- needs to open an encrypted backup. Vault id, backup id, format
 * version, KDF algorithm and cost parameters, and the salt. None of that is secret, and none of it
 * opens anything on its own.
 *
 * What never goes on the sheet: passwords, item contents, TOTP secrets, the vault key. The master
 * password field and the recovery code field are printed as blank ruled lines for the user to fill
 * in by hand, so the paper is only as dangerous as the user chooses to make it.
 *
 * Printing the recovery code automatically is possible but off by default, and the UI requires an
 * explicit opt-in, because a printed code is a complete bypass of the master password.
 */
class RecoveryKitPdf(
    private val appName: String = "SecureVault",
    private val appVersion: String
) {
    private companion object {
        const val PAGE_WIDTH = 595   // A4 at 72 dpi
        const val PAGE_HEIGHT = 842
        const val MARGIN = 48f
        const val INK = 0xFF1A1A1A.toInt()
        const val MUTED = 0xFF6B6B6B.toInt()
        const val RULE = 0xFFCFCFCF.toInt()
        const val ALERT = 0xFF8C2F1E.toInt()
    }

    private val heading = Paint().apply {
        isAntiAlias = true; color = INK; textSize = 26f
        typeface = Typeface.create(Typeface.SERIF, Typeface.BOLD)
    }
    private val sectionTitle = Paint().apply {
        isAntiAlias = true; color = INK; textSize = 13f
        typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.BOLD)
    }
    private val body = Paint().apply {
        isAntiAlias = true; color = INK; textSize = 10.5f
        typeface = Typeface.SANS_SERIF
    }
    private val mutedBody = Paint(body).apply { color = MUTED; textSize = 9.5f }
    private val mono = Paint().apply {
        isAntiAlias = true; color = INK; textSize = 10f; typeface = Typeface.MONOSPACE
    }
    private val alert = Paint(body).apply { color = ALERT; typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.BOLD) }
    private val rule = Paint().apply { color = RULE; strokeWidth = 0.8f }
    private val writeLine = Paint().apply { color = INK; strokeWidth = 1.1f }

    fun write(
        metadata: VaultMetadata,
        output: OutputStream,
        printRecoveryCode: String? = null,
        backupFileName: String? = null
    ) {
        val document = PdfDocument()
        val page = document.startPage(PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, 1).create())
        val canvas = page.canvas
        var y = MARGIN + 12f

        // Masthead
        canvas.drawText("Emergency Recovery Kit", MARGIN, y, heading)
        y += 18f
        canvas.drawText("$appName $appVersion", MARGIN, y, mutedBody)
        y += 12f
        canvas.drawText("Generated ${formatDate(System.currentTimeMillis())}", MARGIN, y, mutedBody)
        y += 14f
        canvas.drawLine(MARGIN, y, PAGE_WIDTH - MARGIN, y, rule)
        y += 24f

        canvas.drawText(
            "Keep this sheet. It holds the settings needed to open an encrypted backup of your vault.",
            MARGIN, y, body
        )
        y += 14f
        canvas.drawText(
            "It does not contain your passwords, and it will not open your vault by itself.",
            MARGIN, y, body
        )
        y += 28f

        // Vault details
        y = section(canvas, y, "Vault details")
        y = keyValue(canvas, y, "Vault name", metadata.name)
        y = keyValue(canvas, y, "Vault ID", metadata.vaultId)
        y = keyValue(canvas, y, "Backup ID", metadata.backupId)
        y = keyValue(canvas, y, "Created", formatDate(metadata.createdAt))
        y = keyValue(canvas, y, "Vault format", "version ${metadata.formatVersion}")
        y = keyValue(canvas, y, "Key derivation", metadata.kdf.describe())
        y = keyValue(canvas, y, "Salt (not secret)", metadata.kdf.saltB64)
        y = keyValue(canvas, y, "Key file required", if (metadata.keyFileRequired) "Yes" else "No")
        backupFileName?.let { y = keyValue(canvas, y, "Backup file", it) }
        y += 16f

        // Handwritten secrets
        y = section(canvas, y, "Write these in yourself")
        canvas.drawText(
            "Nothing below is printed by the app. Fill them in by hand, or leave them blank if you keep them elsewhere.",
            MARGIN, y, mutedBody
        )
        y += 26f
        y = writeField(canvas, y, "Master password")
        y = if (printRecoveryCode != null) {
            canvas.drawText("Emergency recovery code", MARGIN, y, sectionTitle)
            y += 16f
            canvas.drawText(printRecoveryCode, MARGIN, y, mono)
            y += 10f
            canvas.drawText(
                "Printed at your request. Anyone holding this code and a backup file can open your vault.",
                MARGIN, y + 8f, alert
            )
            y + 34f
        } else {
            writeField(canvas, y, "Emergency recovery code")
        }
        y += 12f

        // Restore instructions
        y = section(canvas, y, "How to restore")
        val steps = listOf(
            "Install $appName on the new device.",
            "Choose Restore from backup and select your .securevault file.",
            "Enter your master password. If you enabled a key file, supply that as well.",
            "If you have forgotten the master password, use the emergency recovery code instead -- but only if recovery was enabled before the backup was made.",
            "Once the vault opens, change the master password and generate a fresh recovery kit."
        )
        steps.forEachIndexed { index, step ->
            y = numbered(canvas, y, index + 1, step)
        }
        y += 14f

        // Warnings
        y = section(canvas, y, "Before you put this away")
        canvas.drawText(
            "Store this document in a physically secure location. Anyone who obtains the recovery",
            MARGIN, y, alert
        )
        y += 13f
        canvas.drawText(
            "information may be able to access your vault.",
            MARGIN, y, alert
        )
        y += 18f
        listOf(
            "A backup file without the master password is useless. That is the point -- guard the password, not the file.",
            "There is no reset. Nobody, including the makers of this app, can open your vault without your password or recovery code.",
            "Regenerate this kit after changing your master password; the key derivation settings change with it."
        ).forEach { line -> y = bullet(canvas, y, line) }

        // QR
        drawQr(canvas, metadata)

        canvas.drawLine(MARGIN, PAGE_HEIGHT - 58f, PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 58f, rule)
        canvas.drawText(
            "Recovery metadata only. No passwords, keys or vault contents appear on this sheet.",
            MARGIN, PAGE_HEIGHT - 42f, mutedBody
        )

        document.finishPage(page)
        document.writeTo(output)
        document.close()
    }

    /** Safe metadata only: identifiers and KDF parameters. Verified by eye before shipping. */
    fun qrPayload(metadata: VaultMetadata): String = JSONObject().apply {
        put("v", 1)
        put("app", appName)
        put("vaultId", metadata.vaultId)
        put("backupId", metadata.backupId)
        put("format", metadata.formatVersion)
        put("kdf", metadata.kdf.toJson())
        put("created", metadata.createdAt)
    }.toString()

    private fun drawQr(canvas: Canvas, metadata: VaultMetadata) {
        val size = 118
        val bitmap = renderQr(qrPayload(metadata), size) ?: return
        val left = PAGE_WIDTH - MARGIN - size
        val top = MARGIN + 4f
        canvas.drawBitmap(bitmap, left, top, null)
        canvas.drawText("Recovery metadata", left, top + size + 13f, mutedBody)
        bitmap.recycle()
    }

    private fun renderQr(content: String, size: Int): Bitmap? = runCatching {
        val matrix = QRCodeWriter().encode(
            content, BarcodeFormat.QR_CODE, size, size,
            mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 1)
        )
        Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888).apply {
            for (x in 0 until size) for (y in 0 until size) {
                setPixel(x, y, if (matrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
    }.getOrNull()

    private fun section(canvas: Canvas, y: Float, title: String): Float {
        canvas.drawText(title, MARGIN, y, sectionTitle)
        canvas.drawLine(MARGIN, y + 6f, PAGE_WIDTH - MARGIN, y + 6f, rule)
        return y + 22f
    }

    private fun keyValue(canvas: Canvas, y: Float, key: String, value: String): Float {
        canvas.drawText(key, MARGIN, y, body)
        val valueX = MARGIN + 132f
        val wrapped = wrap(value, mono, PAGE_WIDTH - MARGIN - valueX - 130f)
        wrapped.forEachIndexed { index, line -> canvas.drawText(line, valueX, y + index * 12f, mono) }
        return y + 15f + (wrapped.size - 1) * 12f
    }

    private fun writeField(canvas: Canvas, y: Float, label: String): Float {
        canvas.drawText(label, MARGIN, y, sectionTitle)
        canvas.drawLine(MARGIN, y + 26f, PAGE_WIDTH - MARGIN, y + 26f, writeLine)
        return y + 48f
    }

    private fun numbered(canvas: Canvas, y: Float, index: Int, text: String): Float {
        canvas.drawText("$index.", MARGIN, y, body)
        val x = MARGIN + 18f
        val lines = wrap(text, body, PAGE_WIDTH - MARGIN - x)
        lines.forEachIndexed { i, line -> canvas.drawText(line, x, y + i * 13f, body) }
        return y + 15f + (lines.size - 1) * 13f
    }

    private fun bullet(canvas: Canvas, y: Float, text: String): Float {
        canvas.drawText("\u2022", MARGIN, y, body)
        val x = MARGIN + 12f
        val lines = wrap(text, mutedBody, PAGE_WIDTH - MARGIN - x)
        lines.forEachIndexed { i, line -> canvas.drawText(line, x, y + i * 12f, mutedBody) }
        return y + 14f + (lines.size - 1) * 12f
    }

    private fun wrap(text: String, paint: Paint, maxWidth: Float): List<String> {
        if (text.isEmpty()) return listOf("")
        val words = text.split(' ')
        val lines = mutableListOf<String>()
        var current = StringBuilder()
        val bounds = Rect()
        for (word in words) {
            val candidate = if (current.isEmpty()) word else "$current $word"
            paint.getTextBounds(candidate, 0, candidate.length, bounds)
            if (bounds.width() > maxWidth && current.isNotEmpty()) {
                lines += current.toString()
                current = StringBuilder(word)
            } else {
                current = StringBuilder(candidate)
            }
        }
        if (current.isNotEmpty()) lines += current.toString()
        return lines
    }

    private fun formatDate(millis: Long): String =
        SimpleDateFormat("d MMMM yyyy, HH:mm", Locale.getDefault()).format(Date(millis))
}
