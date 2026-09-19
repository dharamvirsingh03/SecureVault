package app.securevault.feature.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import androidx.annotation.RequiresApi
import app.securevault.di.ServiceLocator

/**
 * Android Autofill provider.
 *
 * Rules this service follows:
 *
 *  - It never returns credentials from a locked vault. When locked it returns an authentication
 *    entry that opens [AutofillAuthActivity]; that activity returns the real response to the
 *    platform once the user has authenticated.
 *  - It only offers items whose stored URL matches the requesting domain, on host boundaries, so
 *    an app showing a login form cannot enumerate the vault and a lookalike domain gets nothing.
 *  - It logs nothing about the request, the fields, or the values.
 *
 * Version limits, stated plainly: this API exists from Android 8.0. Matching a browser page to a
 * vault entry relies on the web domain the browser exposes, which not every browser provides;
 * where it is missing, matching falls back to the package name and may find nothing. Filling TOTP
 * codes is only offered where the platform supplies a recognisable one-time-code hint, which in
 * practice means recent Android versions and well-marked-up forms. None of this has been tested
 * against a real browser yet -- see README.md.
 */
@RequiresApi(Build.VERSION_CODES.O)
class SecureVaultAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }

        val parsed = AutofillStructureParser.parse(structure, captureValues = false)
        if (!parsed.hasCredentialFields) {
            callback.onSuccess(null)
            return
        }

        val session = ServiceLocator.vaultManager(this).session.value
        if (session == null || !session.isAlive) {
            callback.onSuccess(AutofillResponses.authenticationResponse(this, parsed))
            return
        }

        val target = parsed.matchTarget
        if (target.isNullOrBlank()) {
            // No domain and no package to match on. Offering everything here is exactly the
            // enumeration hole this service is supposed to avoid, so offer nothing.
            callback.onSuccess(null)
            return
        }

        val candidates = ServiceLocator.vaultIndex().matchesFor(target)
        callback.onSuccess(AutofillResponses.credentialResponse(this, parsed, candidates))
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // The captured credential is not held anywhere by this service. The user is handed to a
        // confirmation activity which requires an unlocked vault before anything is written.
        val intent = Intent(this, AutofillSaveActivity::class.java)
        val pending = PendingIntent.getActivity(
            this,
            AutofillResponses.REQUEST_SAVE,
            intent,
            // Mutable for the same reason as the auth intent: the platform fills in the
            // AssistStructure carrying the values the user typed.
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT or
                PendingIntent.FLAG_CANCEL_CURRENT
        )
        callback.onSuccess(pending.intentSender)
    }
}
