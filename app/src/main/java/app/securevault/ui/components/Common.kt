package app.securevault.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Article
import androidx.compose.material.icons.filled.Badge
import androidx.compose.material.icons.filled.AccountBalance
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notes
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem

/** One icon per item type, so a list can be scanned without reading every title. */
fun iconFor(type: ItemType): ImageVector = when (type) {
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
fun SectionHeader(text: String, action: (@Composable () -> Unit)? = null) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 20.dp, end = 8.dp, top = 20.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.weight(1f)
        )
        action?.invoke()
    }
}

/**
 * A row in the item list.
 *
 * Shows title, account and host only. Nothing secret appears in a list: not a password, not a
 * masked password, not a TOTP code. A masked value still tells an onlooker how long the secret is
 * and that it exists, and a code on a list screen is a code on screen for as long as the list is.
 */
@Composable
fun ItemRow(
    item: VaultItem,
    onOpen: () -> Unit,
    onToggleFavorite: (() -> Unit)? = null,
    onLongPress: (() -> Unit)? = null
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(onClick = onOpen)
            // One announcement for the row instead of four fragments, and it names the type so a
            // screen-reader user can tell a card from a login without opening either.
            .semantics(mergeDescendants = true) {
                contentDescription = buildString {
                    append(item.type.displayName)
                    append(": ")
                    append(item.title.ifBlank { "Untitled" })
                    subtitleFor(item).takeIf { it.isNotBlank() }?.let { append(", ").append(it) }
                    if (item.favorite) append(", favourite")
                }
            }
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .background(MaterialTheme.colorScheme.secondaryContainer, CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                iconFor(item.type),
                // Decorative: the row already announces the type, so this would be noise.
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.size(20.dp)
            )
        }
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(
                item.title.ifBlank { "Untitled" },
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1
            )
            val subtitle = subtitleFor(item)
            if (subtitle.isNotBlank()) {
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1
                )
            }
            val host = hostOf(item.url)
            if (host.isNotBlank()) {
                Text(
                    host,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1
                )
            }
        }
        if (onToggleFavorite != null) {
            IconButton(onClick = onToggleFavorite, modifier = Modifier.size(48.dp)) {
                Icon(
                    if (item.favorite) Icons.Filled.Star else Icons.Outlined.StarBorder,
                    contentDescription = if (item.favorite) "Remove from favourites" else "Add to favourites",
                    tint = if (item.favorite) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

/** Non-secret identifying detail, chosen per type. Never a secret field. */
internal fun subtitleFor(item: VaultItem): String = when (item.type) {
    ItemType.LOGIN, ItemType.PASSKEY -> item.username
    ItemType.CARD -> listOfNotNull(
        item.payload.field(app.securevault.core.model.Fields.CARD_BRAND).ifBlank { null },
        item.payload.field(app.securevault.core.model.Fields.CARDHOLDER).ifBlank { null }
    ).joinToString(" · ")
    ItemType.IDENTITY -> item.payload.field(app.securevault.core.model.Fields.FULL_NAME)
    ItemType.WIFI -> item.payload.field(app.securevault.core.model.Fields.SSID)
    ItemType.API_KEY -> item.payload.field(app.securevault.core.model.Fields.URL)
    ItemType.BANK_ACCOUNT -> item.payload.field(app.securevault.core.model.Fields.BANK)
    ItemType.SOFTWARE_LICENSE -> item.payload.field(app.securevault.core.model.Fields.LICENCE_OWNER)
    ItemType.SSH_KEY, ItemType.SECURE_NOTE, ItemType.DOCUMENT -> item.type.displayName
}

fun hostOf(url: String): String =
    url.trim().substringAfter("://").substringBefore('/').substringBefore('?').removePrefix("www.")

/**
 * Empty states that say what to do next rather than just reporting nothing.
 */
@Composable
fun EmptyState(
    icon: ImageVector,
    title: String,
    body: String,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            icon,
            contentDescription = null,
            modifier = Modifier.size(44.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(16.dp))
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            body,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        if (actionLabel != null && onAction != null) {
            Spacer(Modifier.height(16.dp))
            TextButton(onClick = onAction) { Text(actionLabel) }
        }
    }
}

/** For anything the user should read before tapping: export warnings, destruction, recovery. */
@Composable
fun WarningCard(text: String, modifier: Modifier = Modifier) {
    Surface(
        // The error container colour carries meaning, so the word "Warning" is prepended for
        // screen readers rather than leaving colour to do the work on its own.
        modifier = modifier.fillMaxWidth().semantics { contentDescription = "Warning. $text" },
        color = MaterialTheme.colorScheme.errorContainer,
        shape = RoundedCornerShape(12.dp)
    ) {
        Text(
            text,
            modifier = Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onErrorContainer
        )
    }
}

@Composable
fun InfoCard(text: String, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = RoundedCornerShape(12.dp)
    ) {
        Text(
            text,
            modifier = Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
