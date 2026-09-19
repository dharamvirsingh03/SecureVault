package app.securevault.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.securevault.feature.generator.PasswordStrength
import app.securevault.ui.VaultViewModel
import app.securevault.ui.theme.SecretTextStyle

@Composable
fun SetupScreen(viewModel: VaultViewModel) {
    var name by remember { mutableStateOf("My vault") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var enableRecovery by remember { mutableStateOf(true) }

    // The one String copy of the master password that this app cannot avoid: Compose's
    // TextField state is String-typed, and there is no CharArray-backed text field. The copy is
    // confined to this composable, converted to a CharArray at the point of use, and dropped when
    // the screen leaves composition. The scoring call below no longer adds a second copy -- see
    // PasswordStrength.CharArrayView. This limitation is recorded in SECURITY.md rather than
    // quietly accepted.
    val strength = PasswordStrength.evaluate(password)
    val matches = password.isNotEmpty() && password == confirm
    val longEnough = password.length >= 12

    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(28.dp)
        ) {
            Text("Create your vault", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Your master password is the only thing that opens this vault. It is never stored, " +
                    "never sent anywhere, and cannot be reset for you.",
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(Modifier.height(24.dp))

            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Vault name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(14.dp))
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Master password") },
                supportingText = { Text("At least 12 characters. A passphrase with spaces works well.") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))

            LinearProgressIndicator(
                progress = { (strength.entropyBits / 120.0).coerceIn(0.0, 1.0).toFloat() },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "${strength.label.name.lowercase().replace('_', ' ')} - ${strength.entropyBits.toInt()} bits",
                style = MaterialTheme.typography.labelMedium
            )
            strength.suggestions.take(2).forEach {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            }

            Spacer(Modifier.height(14.dp))
            OutlinedTextField(
                value = confirm,
                onValueChange = { confirm = it },
                label = { Text("Confirm master password") },
                isError = confirm.isNotEmpty() && !matches,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(22.dp))
            Card {
                Column(Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Create an emergency recovery code", style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "A one-off code that opens the vault if you forget the master password. " +
                                    "It is shown once and never stored in readable form. Anyone holding it " +
                                    "and a backup file can open your vault, so keep it on paper, not on this phone.",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                        Switch(checked = enableRecovery, onCheckedChange = { enableRecovery = it })
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
            Button(
                onClick = { viewModel.createVault(name, password.toCharArray(), enableRecovery); password = ""; confirm = "" },
                enabled = matches && longEnough && name.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) { Text("Create vault") }
            Spacer(Modifier.height(40.dp))
        }
    }
}

/**
 * Shown once, immediately after the code is generated. It cannot be retrieved later.
 *
 * The code stays hidden until the user asks for it. That is not theatre: Compose materialises an
 * immutable String the moment the characters reach a Text, and that String cannot be wiped -- it
 * survives on the heap until garbage collection. Revealing on demand means the String is only
 * created when someone is actually ready to copy the code down, rather than existing for as long
 * as the dialog happens to be open. It also keeps the code off the screen while the phone is
 * being handed around or pointed at.
 */
@Composable
fun RecoveryCodeDialog(code: CharArray, onDismiss: () -> Unit) {
    var acknowledged by remember { mutableStateOf(false) }
    var revealed by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = { },
        title = { Text("Your emergency recovery code") },
        text = {
            Column {
                if (revealed) {
                    // String(code) here is unavoidable. See the note above and SECURITY.md.
                    Text(String(code), style = SecretTextStyle)
                } else {
                    Text("••••-••••-••••-••••-••••-••••-••••-••••", style = SecretTextStyle)
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = { revealed = true }) { Text("Show code") }
                }
                Spacer(Modifier.height(14.dp))
                Text(
                    "Write this down now. It is not stored anywhere you can read it, and it will not " +
                        "be shown again. Keep it away from your backup files -- together they open your vault.",
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = acknowledged, onCheckedChange = { acknowledged = it })
                    Spacer(Modifier.height(0.dp))
                    Text("  I have written it down", style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss, enabled = acknowledged && revealed) { Text("Done") }
        }
    )
}
