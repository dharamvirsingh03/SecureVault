package app.securevault.desktop.platform

import app.securevault.core.vault.VaultMetadata
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.PDPageContentStream
import org.apache.pdfbox.pdmodel.common.PDRectangle
import org.apache.pdfbox.pdmodel.font.PDType1Font
import org.apache.pdfbox.pdmodel.font.Standard14Fonts
import java.io.OutputStream
import java.text.DateFormat
import java.util.Date

/**
 * The emergency recovery kit, rendered with PDFBox.
 *
 * Android uses `android.graphics.pdf`; there is no shared renderer, so the layout code is written
 * twice. What is **not** written twice is the security intent, which is identical and is the part
 * that matters:
 *
 *  - No password, no vault key, no item content, no TOTP secret is written to this file.
 *  - The master password and recovery code are printed as **blank ruled lines to fill in by hand**.
 *    The app never writes either into a file.
 *  - Everything printed is metadata that is already plaintext in the vault header: which KDF and
 *    parameters, the salt, the vault id, the format version. None of it opens anything.
 *
 * The desktop kit deliberately omits the QR code Android prints. It carried the same non-secret
 * metadata and added a dependency purely to render it; the same information is on the page as
 * text. Noted here rather than left as a silent difference.
 */
object RecoveryKitPdf {

    private val TITLE = PDType1Font(Standard14Fonts.FontName.TIMES_BOLD)
    private val HEADING = PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD)
    private val BODY = PDType1Font(Standard14Fonts.FontName.HELVETICA)
    private val MONO = PDType1Font(Standard14Fonts.FontName.COURIER)

    private const val MARGIN = 56f

    // val, not const val: PDRectangle.A4 is an object whose width and height are read at runtime,
    // so they are not compile-time constants. The page size is unchanged -- A4, same as Android.
    private val WIDTH = PDRectangle.A4.width
    private val HEIGHT = PDRectangle.A4.height

    /**
     * @param printedRecoveryCode opt-in only. When supplied, the page opens the vault by itself and
     * a warning is printed beside it. Null means a blank line to write on.
     */
    fun write(metadata: VaultMetadata, output: OutputStream, printedRecoveryCode: String? = null) {
        PDDocument().use { document ->
            val page = PDPage(PDRectangle.A4)
            document.addPage(page)
            PDPageContentStream(document, page).use { out ->
                var y = HEIGHT - MARGIN

                y = text(out, TITLE, 22f, MARGIN, y, "SecureVault Emergency Recovery Kit") - 8f
                y = wrapped(
                    out, BODY, 10f, y,
                    "This document does not contain your passwords. It contains the information " +
                        "needed to recover your vault, plus space to write down the two things " +
                        "SecureVault will never write down for you."
                ) - 18f

                y = text(out, HEADING, 12f, MARGIN, y, "Your vault") - 6f
                y = field(out, y, "Vault name", metadata.name)
                y = field(out, y, "Vault id", metadata.vaultId)
                y = field(out, y, "Created", DateFormat.getDateInstance(DateFormat.LONG).format(Date(metadata.createdAt)))
                y = field(out, y, "Vault format", "version ${metadata.formatVersion}")
                y = field(out, y, "Key derivation", metadata.kdf.describe())
                y = field(out, y, "Salt", metadata.kdf.saltB64)
                y = field(out, y, "Recovery code", if (metadata.recovery != null) "Enabled" else "Not set up")
                y -= 14f

                y = text(out, HEADING, 12f, MARGIN, y, "Write these in by hand") - 10f
                y = ruled(out, y, "Master password")
                y = if (printedRecoveryCode != null) {
                    val printed = field(out, y, "Recovery code", printedRecoveryCode)
                    wrapped(
                        out, BODY, 9f, printed - 4f,
                        "WARNING: your recovery code is printed above, so this page opens your " +
                            "vault on its own. Store it somewhere you would keep a passport."
                    )
                } else {
                    ruled(out, y, "Recovery code")
                }
                y -= 18f

                y = text(out, HEADING, 12f, MARGIN, y, "How to recover") - 8f
                listOf(
                    "1. Install SecureVault on the device you want to recover to.",
                    "2. Choose Restore a backup and select your .securevault file.",
                    "3. Enter the master password written above.",
                    "4. If you have forgotten it, use the recovery code instead.",
                    "5. Without either, the vault cannot be opened. There is no reset and no support path."
                ).forEach { line -> y = wrapped(out, BODY, 10f, y, line) - 2f }
                y -= 16f

                y = text(out, HEADING, 12f, MARGIN, y, "Keep this safe") - 8f
                wrapped(
                    out, BODY, 10f, y,
                    "Anyone holding this page and your backup file has what they need once the " +
                        "blanks are filled in. Store it away from your backups: a page kept in " +
                        "the same drawer as the drive protects nothing."
                )
            }
            document.save(output)
        }
    }

    private fun text(
        out: PDPageContentStream, font: PDType1Font, size: Float, x: Float, y: Float, value: String
    ): Float {
        out.beginText()
        out.setFont(font, size)
        out.newLineAtOffset(x, y)
        out.showText(sanitise(value))
        out.endText()
        return y - size - 4f
    }

    private fun field(out: PDPageContentStream, y: Float, label: String, value: String): Float {
        text(out, BODY, 10f, MARGIN, y, label)
        text(out, MONO, 10f, MARGIN + 150f, y, value)
        return y - 16f
    }

    private fun ruled(out: PDPageContentStream, y: Float, label: String): Float {
        text(out, BODY, 10f, MARGIN, y, label)
        out.moveTo(MARGIN + 150f, y - 3f)
        out.lineTo(WIDTH - MARGIN, y - 3f)
        out.stroke()
        return y - 30f
    }

    private fun wrapped(
        out: PDPageContentStream, font: PDType1Font, size: Float, startY: Float, value: String
    ): Float {
        val maxWidth = WIDTH - 2 * MARGIN
        var y = startY
        val words = sanitise(value).split(" ")
        var line = StringBuilder()
        words.forEach { word ->
            val candidate = if (line.isEmpty()) word else "$line $word"
            val width = font.getStringWidth(candidate) / 1000 * size
            if (width > maxWidth && line.isNotEmpty()) {
                y = text(out, font, size, MARGIN, y, line.toString())
                line = StringBuilder(word)
            } else {
                line = StringBuilder(candidate)
            }
        }
        if (line.isNotEmpty()) y = text(out, font, size, MARGIN, y, line.toString())
        return y
    }

    /** Standard 14 fonts are WinAnsi; anything outside it would throw mid-render. */
    private fun sanitise(value: String) = value.map { if (it.code in 32..255) it else '?' }.joinToString("")
}
