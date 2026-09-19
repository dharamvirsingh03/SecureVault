package app.securevault.desktop.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import app.securevault.core.model.*
import app.securevault.core.vault.VaultSettings
import app.securevault.desktop.LocalAppState
import app.securevault.feature.generator.PasswordGenerator
import app.securevault.feature.generator.PasswordOptions
import app.securevault.feature.generator.PasswordStrength
import app.securevault.feature.totp.OtpAuthUri
import app.securevault.feature.totp.TotpEngine
import kotlinx.coroutines.delay
import java.text.DateFormat
import java.util.Date

// ---- setup / unlock ------------------------------------------------------------------------

@Composable
fun SetupScreen() {
    val state = LocalAppState.current
    var name by remember { mutableStateOf("My vault") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var enableRecovery by remember { mutableStateOf(true) }

    val strength = remember(password) { if (password.isEmpty()) null else PasswordStrength.evaluate(password) }
    val ready = password.length >= 12 && password == confirm && name.isNotBlank()

    Box(Modifier.fillMaxSize().padding(48.dp), contentAlignment = Alignment.Center) {
        Column(Modifier.widthIn(max = 560.dp).verticalScroll(rememberScrollState())) {
            Text("Create your vault", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Your master password is the only thing that opens this vault. It is never stored, " +
                    "never sent anywhere, and cannot be reset for you.",
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(Modifier.height(24.dp))

            OutlinedTextField(name, { name = it }, label = { Text("Vault name") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                password, { password = it }, label = { Text("Master password") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                supportingText = {
                    Text(
                        when {
                            password.length < 12 -> "At least 12 characters. A passphrase of four or five words works well."
                            strength != null -> "${strength.label.name.replace('_', ' ').lowercase()} · ${strength.entropyBits.toInt()} bits"
                            else -> ""
                        }
                    )
                },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                confirm, { confirm = it }, label = { Text("Confirm") }, singleLine = true,
                isError = confirm.isNotEmpty() && confirm != password,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(20.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(enableRecovery, { enableRecovery = it })
                Spacer(Modifier.width(12.dp))
                Text("Generate a recovery code", style = MaterialTheme.typography.bodyMedium)
            }
            Spacer(Modifier.height(8.dp))
            WarningCard(
                "A recovery code is a second way into your vault, not a backup of your password. " +
                    "Anyone holding it and a copy of your vault gets in. Store it away from your backups."
            )
            Spacer(Modifier.height(24.dp))
            Button({ state.createVault(name.trim(), password.toCharArray(), enableRecovery) }, enabled = ready) {
                Text("Create vault")
            }
        }
    }
}

@Composable
fun UnlockScreen(error: String?, lockoutSeconds: Long, busy: Boolean) {
    val state = LocalAppState.current
    var password by remember { mutableStateOf("") }
    var showRecovery by remember { mutableStateOf(false) }
    var recovery by remember { mutableStateOf("") }
    val focus = remember { FocusRequester() }

    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }

    Box(Modifier.fillMaxSize().padding(48.dp), contentAlignment = Alignment.Center) {
        Column(
            Modifier.widthIn(max = 420.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Image(
                painterResource("icons/securevault-128.png"),
                contentDescription = "SecureVault",
                modifier = Modifier.size(72.dp)
            )
            Spacer(Modifier.height(16.dp))
            Text("SecureVault", style = MaterialTheme.typography.headlineSmall)
            Text("Vault locked", style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(28.dp))

            OutlinedTextField(
                password, { password = it },
                label = { Text("Master password") },
                singleLine = true,
                enabled = !busy && lockoutSeconds <= 0,
                isError = error != null,
                visualTransformation = PasswordVisualTransformation(),
                supportingText = {
                    when {
                        lockoutSeconds > 0 -> Text("Locked out for ${lockoutSeconds}s")
                        error != null -> Text(error)
                        else -> {}
                    }
                },
                modifier = Modifier.fillMaxWidth().focusRequester(focus)
            )
            Spacer(Modifier.height(16.dp))
            Button(
                { state.unlock(password.toCharArray()); password = "" },
                enabled = password.isNotEmpty() && !busy && lockoutSeconds <= 0,
                modifier = Modifier.fillMaxWidth()
            ) { Text(if (busy) "Unlocking" else "Unlock") }

            if (state.hasRecovery()) {
                Spacer(Modifier.height(8.dp))
                TextButton({ showRecovery = !showRecovery }) { Text("Use a recovery code") }
                if (showRecovery) {
                    OutlinedTextField(
                        recovery, { recovery = it.uppercase() },
                        label = { Text("Recovery code") }, singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(8.dp))
                    Button(
                        { state.unlockWithRecoveryCode(recovery.toCharArray()); recovery = "" },
                        enabled = recovery.isNotBlank(), modifier = Modifier.fillMaxWidth()
                    ) { Text("Unlock with recovery code") }
                }
            }
        }
    }
}

@Composable
fun RecoveryCodeDialog(code: CharArray, onDismiss: () -> Unit) {
    var acknowledged by remember { mutableStateOf(false) }
    var revealed by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = {},
        title = { Text("Your emergency recovery code") },
        text = {
            Column {
                if (revealed) {
                    // Rendering necessarily creates an immutable String the JVM cannot wipe.
                    // Revealing on demand keeps that copy as short-lived as possible.
                    SelectionText(String(code))
                } else {
                    Text("••••-••••-••••-••••-••••-••••-••••-••••", fontFamily = FontFamily.Monospace)
                    Spacer(Modifier.height(8.dp))
                    TextButton({ revealed = true }) { Text("Show code") }
                }
                Spacer(Modifier.height(16.dp))
                WarningCard(
                    "Write this down now. It is shown once and cannot be retrieved later. " +
                        "It opens your vault on its own, so keep it away from your backups."
                )
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(acknowledged, { acknowledged = it })
                    Text("I have written it down", style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            TextButton(onDismiss, enabled = acknowledged && revealed) { Text("Done") }
        }
    )
}

@Composable
private fun SelectionText(value: String) {
    androidx.compose.foundation.text.selection.SelectionContainer {
        Text(value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
    }
}

// ---- vault: master-detail --------------------------------------------------------------------

@Composable
fun VaultScreen() {
    val state = LocalAppState.current
    val filter by state.filter.collectAsState()
    val visible by state.visibleItems.collectAsState()
    val folders by state.folders.collectAsState()

    var selectedId by remember { mutableStateOf<String?>(null) }
    var editing by remember { mutableStateOf<Pair<String?, ItemType>?>(null) }
    var showAdd by remember { mutableStateOf(false) }
    val searchFocus = remember { FocusRequester() }

    editing?.let { (id, type) ->
        ItemEditorDialog(id, type) { editing = null }
        return
    }

    Row(Modifier.fillMaxSize()) {
        Column(Modifier.width(380.dp).fillMaxHeight()) {
            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    filter.query,
                    { q -> state.setFilter { it.copy(query = q) } },
                    placeholder = { Text("Search your vault") },
                    leadingIcon = { Icon(Icons.Filled.Search, null) },
                    singleLine = true,
                    modifier = Modifier.weight(1f).focusRequester(searchFocus)
                )
                Spacer(Modifier.width(8.dp))
                FilledIconButton({ showAdd = true }) {
                    Icon(Icons.Filled.Add, contentDescription = "New item (Ctrl+N)")
                }
            }

            TypeFilterRow(state)

            if (visible.isEmpty()) {
                Column(Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Spacer(Modifier.height(40.dp))
                    Text(
                        if (state.allItems().isEmpty()) "Your vault is empty" else "Nothing matches",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        if (state.allItems().isEmpty())
                            "Add your first login, or import from another manager under Backup & data."
                        else "Search covers names, usernames, websites, tags and folders — never passwords.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(16.dp))
                    TextButton({ showAdd = true }) { Text("Add an item") }
                }
            } else {
                LazyColumn(Modifier.fillMaxSize()) {
                    items(visible, key = { it.id }) { item ->
                        ItemRow(item, item.id == selectedId) { selectedId = item.id }
                    }
                }
            }
        }
        VerticalDivider()
        Box(Modifier.weight(1f).fillMaxHeight()) {
            val selected = selectedId?.let { state.itemById(it) }
            if (selected == null) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        "Select an item",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                ItemDetail(selected, onEdit = { editing = selected.id to selected.type },
                    onDeleted = { selectedId = null })
            }
        }
    }

    if (showAdd) {
        AddItemDialog(
            onPick = { type -> showAdd = false; editing = null to type },
            onDismiss = { showAdd = false }
        )
    }
}

// FlowRow (item-type filter chips) is still an experimental layout API.
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TypeFilterRow(state: app.securevault.desktop.AppState) {
    val filter by state.filter.collectAsState()
    val counts = state.countsByType()
    FlowRow(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        FilterChip(filter.type == null && !filter.favoritesOnly,
            { state.setFilter { it.copy(type = null, favoritesOnly = false) } }, { Text("All") })
        FilterChip(filter.favoritesOnly,
            { state.setFilter { it.copy(favoritesOnly = !it.favoritesOnly, type = null) } },
            { Text("Favourites") })
        ItemType.entries.filter { counts.getOrDefault(it, 0) > 0 }.forEach { type ->
            FilterChip(
                filter.type == type,
                { state.setFilter { f -> f.copy(type = if (f.type == type) null else type) } },
                { Text("${type.displayName} ${counts[type]}") }
            )
        }
    }
}

@Composable
private fun ItemRow(item: VaultItem, selected: Boolean, onClick: () -> Unit) {
    val state = LocalAppState.current
    ListItem(
        headlineContent = { Text(item.title.ifBlank { "Untitled" }) },
        supportingContent = {
            // Non-secret detail only. Never a password, not even masked: a masked value still
            // reveals its length and that it exists.
            val subtitle = listOfNotNull(
                item.username.ifBlank { null },
                item.url.ifBlank { null }?.substringAfter("://")?.substringBefore('/')
            ).joinToString(" · ")
            if (subtitle.isNotBlank()) Text(subtitle)
        },
        leadingContent = { Icon(iconFor(item.type), contentDescription = item.type.displayName) },
        trailingContent = {
            IconButton({ state.toggleFavorite(item) }) {
                Icon(
                    if (item.favorite) Icons.Filled.Star else Icons.Filled.StarBorder,
                    contentDescription = if (item.favorite) "Remove from favourites" else "Add to favourites"
                )
            }
        },
        colors = if (selected) ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
        else ListItemDefaults.colors(),
        modifier = Modifier.clickable(onClick = onClick)
    )
}

fun iconFor(type: ItemType) = when (type) {
    ItemType.LOGIN -> Icons.Filled.Lock
    ItemType.CARD -> Icons.Filled.CreditCard
    ItemType.IDENTITY -> Icons.Filled.Badge
    ItemType.SECURE_NOTE -> Icons.Filled.Notes
    ItemType.WIFI -> Icons.Filled.Wifi
    ItemType.API_KEY -> Icons.Filled.Key
    ItemType.SSH_KEY -> Icons.Filled.Terminal
    ItemType.BANK_ACCOUNT -> Icons.Filled.AccountBalance
    ItemType.SOFTWARE_LICENSE -> Icons.Filled.VerifiedUser
    ItemType.DOCUMENT -> Icons.Filled.Article
    ItemType.PASSKEY -> Icons.Filled.Password
}

@Composable
private fun AddItemDialog(onPick: (ItemType) -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add to your vault") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                // Passkeys are absent: the provider is not implemented, on either platform.
                ItemSchema.CREATABLE.forEach { type ->
                    ListItem(
                        headlineContent = { Text(type.displayName) },
                        supportingContent = { Text(ItemSchema.titleHintFor(type)) },
                        leadingContent = { Icon(iconFor(type), null) },
                        modifier = Modifier.clickable { onPick(type) }
                    )
                }
            }
        },
        confirmButton = { TextButton(onDismiss) { Text("Cancel") } }
    )
}
