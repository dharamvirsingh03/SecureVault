package app.securevault.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.securevault.feature.health.HealthIssue
import app.securevault.feature.health.HealthReport
import app.securevault.core.model.VaultItem
import app.securevault.ui.VaultViewModel
import app.securevault.ui.components.EmptyState
import app.securevault.ui.components.InfoCard
import app.securevault.ui.components.ItemRow
import app.securevault.ui.components.SectionHeader
import app.securevault.ui.nav.IssueCategory

/**
 * Password health.
 *
 * Every number here is computed on device from decrypted items already in memory. The one
 * exception is the breach check, which is opt-in and explained before it runs.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityScreen(
    viewModel: VaultViewModel,
    onOpenCategory: (IssueCategory) -> Unit
) {
    val report by viewModel.health.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val busy by viewModel.busy.collectAsState()

    LaunchedEffect(Unit) { viewModel.refreshHealth() }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Security") }) }
    ) { padding ->
        val current = report
        if (current == null) {
            Column(Modifier.fillMaxSize().padding(padding)) {
                EmptyState(
                    icon = Icons.Filled.Shield,
                    title = "Nothing to check yet",
                    body = "Add some logins and SecureVault will look for weak, reused, old and " +
                        "unprotected passwords."
                )
            }
            return@Scaffold
        }

        LazyColumn(Modifier.fillMaxSize().padding(padding)) {
            item { ScoreHeader(current) }

            item { SectionHeader("What to look at") }
            item {
                IssueLine("Weak passwords", current.weak.size, IssueCategory.WEAK, onOpenCategory)
                IssueLine("Reused passwords", current.reused.size, IssueCategory.REUSED, onOpenCategory)
                IssueLine("Old passwords", current.old.size, IssueCategory.OLD, onOpenCategory)
                IssueLine(
                    "Missing two-factor", current.missingTwoFactor.size,
                    IssueCategory.MISSING_2FA, onOpenCategory
                )
                if (current.breachCheckRan) {
                    IssueLine(
                        "Found in a breach", current.breached.size,
                        IssueCategory.BREACHED, onOpenCategory
                    )
                }
            }

            if (current.weak.isEmpty() && current.reused.isEmpty() && current.old.isEmpty() &&
                current.missingTwoFactor.isEmpty() && current.breached.isEmpty()
            ) {
                item {
                    Column(
                        Modifier.fillMaxWidth().padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            Icons.Filled.CheckCircle,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(Modifier.height(8.dp))
                        Text("You're looking good", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "No major password security issues were found.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            item { SectionHeader("Breach check") }
            item {
                Column(Modifier.padding(horizontal = 20.dp)) {
                    InfoCard(
                        "This is the only thing in SecureVault that touches the network, and it is " +
                            "off until you turn it on. When it runs, the first five characters of " +
                            "each password's SHA-1 hash are sent to Have I Been Pwned; the service " +
                            "returns every match for that prefix and the comparison happens here. " +
                            "It never receives a password, a full hash, a username or a site. " +
                            "What it can still see: that someone at your IP asked, and when."
                    )
                    Spacer(Modifier.height(12.dp))
                    if (settings.breachCheckEnabled) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { viewModel.runBreachCheck() },
                                enabled = busy == null
                            ) { Text(if (busy == null) "Check now" else "Checking") }
                            TextButton(onClick = {
                                viewModel.updateSettings(settings.copy(breachCheckEnabled = false))
                            }) { Text("Turn off") }
                        }
                    } else {
                        Button(onClick = {
                            viewModel.updateSettings(settings.copy(breachCheckEnabled = true))
                        }) { Text("Turn on breach checking") }
                    }
                    if (current.breachCheckRan) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Last check found ${current.breached.size} affected " +
                                "${if (current.breached.size == 1) "password" else "passwords"}.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
            item { Spacer(Modifier.height(40.dp)) }
        }
    }
}

@Composable
private fun ScoreHeader(report: HealthReport) {
    Column(Modifier.fillMaxWidth().padding(20.dp)) {
        Text("${report.score}", style = MaterialTheme.typography.displayMedium)
        Text(report.label, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        LinearProgressIndicator(
            progress = { report.score / 100f },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "Across ${report.totalWithPasswords} " +
                "${if (report.totalWithPasswords == 1) "item" else "items"} with a password.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun IssueLine(
    label: String,
    count: Int,
    category: IssueCategory,
    onOpen: (IssueCategory) -> Unit
) {
    ListItem(
        headlineContent = { Text(label) },
        trailingContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "$count",
                    style = MaterialTheme.typography.titleMedium,
                    color = if (count == 0) MaterialTheme.colorScheme.onSurfaceVariant
                    else MaterialTheme.colorScheme.error
                )
                Icon(Icons.Filled.ChevronRight, contentDescription = null)
            }
        },
        modifier = Modifier.fillMaxWidth().clickable(enabled = count > 0) { onOpen(category) }
    )
}

/** The drill-down list for one category. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityIssuesScreen(
    viewModel: VaultViewModel,
    category: IssueCategory,
    onBack: () -> Unit,
    onOpenItem: (VaultItem) -> Unit
) {
    val report by viewModel.health.collectAsState()
    val issues: List<HealthIssue> = when (category) {
        IssueCategory.WEAK -> report?.weak
        IssueCategory.REUSED -> report?.reused
        IssueCategory.OLD -> report?.old
        IssueCategory.MISSING_2FA -> report?.missingTwoFactor
        IssueCategory.BREACHED -> report?.breached
    }.orEmpty()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(category.title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        if (issues.isEmpty()) {
            Column(Modifier.fillMaxSize().padding(padding)) {
                EmptyState(
                    icon = Icons.Filled.CheckCircle,
                    title = "Nothing here",
                    body = "No items fall into this category right now."
                )
            }
        } else {
            LazyColumn(Modifier.fillMaxSize().padding(padding)) {
                items(issues, key = { it.item.id }) { issue ->
                    Column {
                        ItemRow(issue.item, onOpen = { onOpenItem(issue.item) })
                        Text(
                            issue.detail,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(start = 74.dp, end = 20.dp, bottom = 8.dp)
                        )
                    }
                }
            }
        }
    }
}
