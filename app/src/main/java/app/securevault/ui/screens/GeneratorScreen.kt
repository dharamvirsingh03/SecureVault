package app.securevault.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import app.securevault.feature.generator.PassphraseGenerator
import app.securevault.feature.generator.PassphraseOptions
import app.securevault.feature.generator.PasswordGenerator
import app.securevault.feature.generator.PasswordOptions
import app.securevault.feature.generator.AssetWordSource
import app.securevault.feature.generator.WordLists
import app.securevault.platform.CopyKind
import app.securevault.ui.VaultViewModel
import app.securevault.ui.theme.SecretTextStyle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GeneratorScreen(viewModel: VaultViewModel, onUseInLogin: (() -> Unit)? = null) {
    val context = LocalContext.current
    val words = remember { AssetWordSource(context).words() }
    var passphraseMode by remember { mutableStateOf(false) }
    var options by remember { mutableStateOf(PasswordOptions()) }
    var phraseOptions by remember { mutableStateOf(PassphraseOptions()) }
    var value by remember { mutableStateOf(PasswordGenerator.generate(PasswordOptions())) }

    fun regenerate() {
        value = if (passphraseMode) PassphraseGenerator.generate(phraseOptions, words)
        else runCatching { PasswordGenerator.generate(options) }.getOrElse { value }
    }

    val entropy = if (passphraseMode) PassphraseGenerator.entropyBits(phraseOptions, words.size)
    else PasswordGenerator.entropyBits(options)

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp)) {
        Text("Generator", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(18.dp)) {
                Text(value, style = SecretTextStyle)
                Spacer(Modifier.height(12.dp))
                Text("${entropy.toInt()} bits of entropy", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(onClick = { regenerate() }) { Text("Generate") }
                    OutlinedButton(onClick = { viewModel.copy(value, CopyKind.PASSWORD) }) { Text("Copy") }
                }
                if (onUseInLogin != null) {
                    Spacer(Modifier.height(10.dp))
                    OutlinedButton(
                        onClick = {
                            // Handed over in memory, never through the route. See
                            // VaultViewModel.stageGeneratedPassword.
                            viewModel.stageGeneratedPassword(value)
                            onUseInLogin()
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Use in a new login") }
                }
            }
        }

        Spacer(Modifier.height(20.dp))
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            SegmentedButton(
                selected = !passphraseMode,
                onClick = { passphraseMode = false; regenerate() },
                shape = SegmentedButtonDefaults.itemShape(0, 2)
            ) { Text("Password") }
            SegmentedButton(
                selected = passphraseMode,
                onClick = { passphraseMode = true; regenerate() },
                shape = SegmentedButtonDefaults.itemShape(1, 2)
            ) { Text("Passphrase") }
        }

        Spacer(Modifier.height(20.dp))
        if (!passphraseMode) {
            Text("Length: ${options.length}", style = MaterialTheme.typography.titleSmall)
            Slider(
                value = options.length.toFloat(),
                onValueChange = { options = options.copy(length = it.toInt()); regenerate() },
                valueRange = 8f..64f
            )
            ToggleRow("Uppercase", options.uppercase) { options = options.copy(uppercase = it); regenerate() }
            ToggleRow("Lowercase", options.lowercase) { options = options.copy(lowercase = it); regenerate() }
            ToggleRow("Numbers", options.numbers) { options = options.copy(numbers = it); regenerate() }
            ToggleRow("Symbols", options.symbols) { options = options.copy(symbols = it); regenerate() }
            ToggleRow("Avoid lookalike characters", options.avoidAmbiguous) {
                options = options.copy(avoidAmbiguous = it); regenerate()
            }
        } else {
            Text("Words: ${phraseOptions.words}", style = MaterialTheme.typography.titleSmall)
            Slider(
                value = phraseOptions.words.toFloat(),
                onValueChange = { phraseOptions = phraseOptions.copy(words = it.toInt()); regenerate() },
                valueRange = 3f..10f
            )
            ToggleRow("Capitalise words", phraseOptions.capitalise) {
                phraseOptions = phraseOptions.copy(capitalise = it); regenerate()
            }
            ToggleRow("Add a number", phraseOptions.includeNumber) {
                phraseOptions = phraseOptions.copy(includeNumber = it); regenerate()
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("-", ".", "_", " ").forEach { separator ->
                    OutlinedButton(onClick = {
                        phraseOptions = phraseOptions.copy(separator = separator); regenerate()
                    }) { Text(if (separator == " ") "space" else separator) }
                }
            }
            if (!WordLists.isFullDicewareList(words)) {
                Spacer(Modifier.height(12.dp))
                Text(
                    "Using the built-in ${words.size}-word list. Add the EFF large wordlist to assets " +
                        "for full diceware strength.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary
                )
            }
        }
        Spacer(Modifier.height(40.dp))
    }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Text(label, style = MaterialTheme.typography.bodyLarge)
    }
}
