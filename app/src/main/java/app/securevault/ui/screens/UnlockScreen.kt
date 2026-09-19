package app.securevault.ui.screens

import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.securevault.ui.UnlockState
import app.securevault.ui.VaultViewModel

@Composable
fun UnlockScreen(viewModel: VaultViewModel) {
    val state by viewModel.unlockState.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val context = LocalContext.current
    var password by remember { mutableStateOf("") }
    var showRecovery by remember { mutableStateOf(false) }
    var recoveryCode by remember { mutableStateOf("") }

    val locked = state as? UnlockState.Locked

    Surface(Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().padding(28.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.Start
        ) {
            Text(
                text = viewModel.vaultMetadata()?.name ?: "Vault",
                style = MaterialTheme.typography.headlineMedium
            )
            Spacer(Modifier.height(6.dp))
            Text("Locked", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
            Spacer(Modifier.height(28.dp))

            if (!showRecovery) {
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Master password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = {
                        viewModel.unlock(password.toCharArray())
                        password = ""
                    },
                    enabled = password.isNotEmpty() && state !is UnlockState.Unlocking &&
                        (locked?.lockoutSeconds ?: 0L) == 0L,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (state is UnlockState.Unlocking) "Opening vault" else "Unlock")
                }

                if (settings.biometricUnlockEnabled && viewModel.isBiometricConfigured()) {
                    Spacer(Modifier.height(10.dp))
                    OutlinedButton(
                        onClick = { promptBiometric(context, viewModel) },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Use biometrics") }
                }

                Spacer(Modifier.height(12.dp))
                TextButton(onClick = { showRecovery = true }) { Text("Use an emergency recovery code") }
            } else {
                Text(
                    "A recovery code opens the vault without the master password. Use it only if the " +
                        "password is genuinely lost, then set a new one.",
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = recoveryCode,
                    onValueChange = { recoveryCode = it.uppercase() },
                    label = { Text("Recovery code") },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = { viewModel.unlockWithRecoveryCode(recoveryCode.toCharArray()) },
                    enabled = recoveryCode.length >= 16,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Recover vault") }
                Spacer(Modifier.height(8.dp))
                TextButton(onClick = { showRecovery = false }) { Text("Back to password") }
            }

            locked?.error?.let { error ->
                Spacer(Modifier.height(18.dp))
                Text(
                    text = if (locked.lockoutSeconds > 0) {
                        "$error. Try again in ${locked.lockoutSeconds} seconds."
                    } else error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
    }
}

/**
 * The prompt returns an authenticated Cipher bound to the Keystore key. Nothing is decrypted until
 * the platform confirms the biometric, and the master password is never involved in this path.
 */
private fun promptBiometric(context: android.content.Context, viewModel: VaultViewModel) {
    val activity = context as? FragmentActivity ?: return
    val cipher = viewModel.biometricDecryptCipher() ?: return
    val prompt = BiometricPrompt(
        activity,
        ContextCompat.getMainExecutor(context),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                result.cryptoObject?.cipher?.let { viewModel.completeBiometricUnlock(it) }
            }
        }
    )
    prompt.authenticate(
        BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock vault")
            .setSubtitle("Use your fingerprint or face to open the vault")
            .setNegativeButtonText("Use master password")
            .setConfirmationRequired(false)
            .build(),
        BiometricPrompt.CryptoObject(cipher)
    )
}
