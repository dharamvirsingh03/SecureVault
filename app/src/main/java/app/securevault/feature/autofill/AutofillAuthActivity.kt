package app.securevault.feature.autofill

import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.autofill.AutofillManager
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.viewmodel.compose.viewModel
import app.securevault.di.ServiceLocator
import app.securevault.platform.SecureScreen
import app.securevault.ui.UnlockState
import app.securevault.ui.VaultViewModel
import app.securevault.ui.screens.UnlockScreen
import app.securevault.ui.theme.SecureVaultTheme

/**
 * The activity the platform launches when autofill needs an unlocked vault.
 *
 * The contract, which the previous code got wrong in both directions:
 *
 *  1. The launching PendingIntent must be MUTABLE, or the framework cannot attach
 *     EXTRA_ASSIST_STRUCTURE and this activity has nothing to work from.
 *  2. This activity must hand back a FillResponse via EXTRA_AUTHENTICATION_RESULT in setResult.
 *     Simply unlocking and finishing leaves the platform with nothing and the user with an
 *     autofill picker that did nothing.
 *
 * It is a separate activity from MainActivity on purpose. MainActivity is singleTask, and
 * setResult on a singleTask activity does not reliably reach the caller; the result would be
 * dropped exactly when the user thought it had worked.
 */
@RequiresApi(Build.VERSION_CODES.O)
class AutofillAuthActivity : FragmentActivity() {

    private var parsed: ParsedFields? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Default to cancelled: every path that is not an explicit success leaves it this way.
        setResult(Activity.RESULT_CANCELED)

        parsed = readRequest(intent)
        if (parsed == null) {
            finish()
            return
        }

        setContent {
            val viewModel: VaultViewModel = viewModel(factory = VaultViewModel.factory(application))
            val settings by viewModel.settings.collectAsState()
            val unlockState by viewModel.unlockState.collectAsState()

            SecureVaultTheme(theme = settings.theme) {
                SecureScreen(enabled = settings.screenshotProtection)
                // Only the unlock surface is ever shown here. The vault contents are not
                // reachable from an activity another app caused to be launched.
                if (unlockState == UnlockState.Unlocked) {
                    // Side effect, not a composition-time call: finishing the activity from
                    // inside composition would run on every recomposition.
                    LaunchedEffect(Unit) { deliverAndFinish() }
                } else {
                    UnlockScreen(viewModel)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        readRequest(intent)?.let { parsed = it }
    }

    private fun readRequest(intent: Intent?): ParsedFields? {
        val structure: AssistStructure = intent
            ?.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
            ?: return null
        return runCatching { AutofillStructureParser.parse(structure, captureValues = false) }
            .getOrNull()
            ?.takeIf { it.hasCredentialFields }
    }

    private fun deliverAndFinish() {
        val request = parsed
        if (request == null) {
            finish()
            return
        }
        val target = request.matchTarget
        val candidates = if (target.isNullOrBlank()) {
            emptyList()
        } else {
            ServiceLocator.vaultIndex().matchesFor(target)
        }

        val response = AutofillResponses.credentialResponse(
            context = this,
            parsed = request,
            candidates = candidates,
            // The save prompt belongs to the original fill request, not to this authentication
            // round trip; re-attaching it here produces a duplicate save offer.
            includeSaveInfo = false
        )

        if (response != null) {
            setResult(
                Activity.RESULT_OK,
                Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
            )
        }
        // When there is no match the result stays RESULT_CANCELED: the vault is unlocked, but
        // this site has no entry, and inventing one would be worse than the picker closing.
        finish()
    }
}
