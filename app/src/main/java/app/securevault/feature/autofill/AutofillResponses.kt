package app.securevault.feature.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.annotation.RequiresApi
import app.securevault.R
import app.securevault.core.model.VaultItem
import app.securevault.feature.totp.TotpEngine

/**
 * Builds the two kinds of FillResponse this service returns.
 *
 * Both the service (vault locked) and the authentication activity (vault just unlocked) need to
 * produce a response for the same request, so the construction lives here rather than being
 * duplicated and drifting.
 */
@RequiresApi(Build.VERSION_CODES.O)
object AutofillResponses {

    /** Datasets are capped: a picker is not a place to page through a vault. */
    private const val MAX_DATASETS = 8

    /**
     * Response shown while the vault is locked: a single entry that launches authentication.
     *
     * The PendingIntent must be MUTABLE. The platform adds EXTRA_ASSIST_STRUCTURE and
     * EXTRA_CLIENT_STATE to this intent before launching it, and an immutable PendingIntent
     * silently arrives with none of them -- which is why the previous FLAG_IMMUTABLE version could
     * never have worked, no matter what the activity did with it.
     */
    fun authenticationResponse(context: Context, parsed: ParsedFields): FillResponse? {
        if (!parsed.hasCredentialFields) return null

        val presentation = RemoteViews(context.packageName, R.layout.autofill_entry).apply {
            setTextViewText(R.id.autofill_label, context.getString(R.string.autofill_unlock_prompt))
        }

        val intent = Intent(context, AutofillAuthActivity::class.java)
        val pending = PendingIntent.getActivity(
            context,
            REQUEST_AUTH,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT or
                PendingIntent.FLAG_CANCEL_CURRENT
        )

        return FillResponse.Builder()
            .setAuthentication(parsed.autofillIds, pending.intentSender, presentation)
            .build()
    }

    /**
     * Response for an unlocked vault.
     *
     * Only items whose stored URL matches the requesting domain are included. Returning anything
     * broader would let any app that shows a login form enumerate the vault one request at a time.
     */
    fun credentialResponse(
        context: Context,
        parsed: ParsedFields,
        candidates: List<VaultItem>,
        includeSaveInfo: Boolean = true
    ): FillResponse? {
        if (candidates.isEmpty()) return null

        val builder = FillResponse.Builder()
        candidates.take(MAX_DATASETS).forEach { item ->
            builder.addDataset(datasetFor(context, item, parsed))
        }
        if (includeSaveInfo) saveInfo(parsed)?.let { builder.setSaveInfo(it) }
        return builder.build()
    }

    private fun datasetFor(context: Context, item: VaultItem, parsed: ParsedFields): Dataset {
        val presentation = RemoteViews(context.packageName, R.layout.autofill_entry).apply {
            // The label shows the account, never the secret.
            val label = if (item.username.isBlank()) item.title else "${item.title} — ${item.username}"
            setTextViewText(R.id.autofill_label, label)
        }
        val builder = Dataset.Builder(presentation)
        parsed.usernameId?.let {
            builder.setValue(it, AutofillValue.forText(item.username), presentation)
        }
        parsed.passwordId?.let {
            builder.setValue(it, AutofillValue.forText(item.password), presentation)
        }
        parsed.otpId?.let { id ->
            item.payload.totp?.let { config ->
                builder.setValue(id, AutofillValue.forText(TotpEngine.generate(config).code), presentation)
            }
        }
        return builder.build()
    }

    private fun saveInfo(parsed: ParsedFields): SaveInfo? {
        val ids = listOfNotNull(parsed.usernameId, parsed.passwordId)
        if (ids.isEmpty()) return null
        val type = when {
            parsed.usernameId != null && parsed.passwordId != null ->
                SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD
            parsed.passwordId != null -> SaveInfo.SAVE_DATA_TYPE_PASSWORD
            else -> SaveInfo.SAVE_DATA_TYPE_USERNAME
        }
        return SaveInfo.Builder(type, ids.toTypedArray()).build()
    }

    const val REQUEST_AUTH = 1001
    const val REQUEST_SAVE = 1002
}
