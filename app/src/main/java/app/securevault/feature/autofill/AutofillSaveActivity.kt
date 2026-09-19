package app.securevault.feature.autofill

import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.autofill.AutofillManager
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.viewmodel.compose.viewModel
import app.securevault.core.model.Fields
import app.securevault.core.model.ItemPayload
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.platform.SecureScreen
import app.securevault.ui.UnlockState
import app.securevault.ui.VaultViewModel
import app.securevault.ui.screens.UnlockScreen
import app.securevault.ui.theme.SecureVaultTheme

/**
 * Confirms and stores a credential the platform captured from a login form.
 *
 * Nothing is written without an unlocked vault and an explicit tap. The captured password is held
 * only for the lifetime of this activity, is never shown, never logged, and never leaves it except
 * as ciphertext through the normal repository path.
 */
@RequiresApi(Build.VERSION_CODES.O)
class AutofillSaveActivity : FragmentActivity() {

    private var captured: ParsedFields? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(Activity.RESULT_CANCELED)

        captured = readCapture(intent)
        val request = captured
        if (request?.passwordValue.isNullOrBlank()) {
            // Nothing worth saving, or the platform gave us no values.
            finish()
            return
        }

        setContent {
            val viewModel: VaultViewModel = viewModel(factory = VaultViewModel.factory(application))
            val settings by viewModel.settings.collectAsState()
            val unlockState by viewModel.unlockState.collectAsState()

            SecureVaultTheme(theme = settings.theme) {
                SecureScreen(enabled = settings.screenshotProtection)
                when (unlockState) {
                    UnlockState.Unlocked -> ConfirmSave(
                        site = request.matchTarget.orEmpty(),
                        username = request.usernameValue.orEmpty(),
                        onSave = { save(viewModel, request) },
                        onCancel = { finish() }
                    )
                    else -> UnlockScreen(viewModel)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        readCapture(intent)?.let { captured = it }
    }

    private fun readCapture(intent: Intent?): ParsedFields? {
        val structure: AssistStructure = intent
            ?.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
            ?: return null
        return runCatching { AutofillStructureParser.parse(structure, captureValues = true) }.getOrNull()
    }

    private fun save(viewModel: VaultViewModel, request: ParsedFields) {
        val site = request.matchTarget.orEmpty()
        val item = VaultItem(
            type = ItemType.LOGIN,
            payload = ItemPayload(
                title = AutofillDomainMatcher.hostOf(site).ifBlank { site }.ifBlank { "Saved login" },
                fields = buildMap {
                    request.usernameValue?.takeIf { it.isNotBlank() }?.let { put(Fields.USERNAME, it) }
                    request.passwordValue?.takeIf { it.isNotBlank() }?.let { put(Fields.PASSWORD, it) }
                    if (site.isNotBlank()) put(Fields.URL, site)
                },
                passwordChangedAt = System.currentTimeMillis()
            )
        )
        viewModel.save(item)
        setResult(Activity.RESULT_OK)
        finish()
    }

    @Composable
    private fun ConfirmSave(
        site: String,
        username: String,
        onSave: () -> Unit,
        onCancel: () -> Unit
    ) {
        Surface(Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center
            ) {
                Text("Save this login?", style = MaterialTheme.typography.headlineSmall)
                Spacer(Modifier.height(16.dp))
                if (site.isNotBlank()) {
                    Text(site, style = MaterialTheme.typography.bodyLarge)
                }
                if (username.isNotBlank()) {
                    Text(username, style = MaterialTheme.typography.bodyMedium)
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "The password will be encrypted with your vault key. It is not shown here.",
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(Modifier.height(24.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(onClick = onSave) { Text("Save to vault") }
                    TextButton(onClick = onCancel) { Text("Not now") }
                }
            }
        }
    }
}
