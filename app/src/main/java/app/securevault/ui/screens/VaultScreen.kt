package app.securevault.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Sell
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.securevault.core.model.ItemSchema
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.ui.VaultViewModel
import app.securevault.ui.components.EmptyState
import app.securevault.ui.components.ItemRow
import app.securevault.ui.components.SectionHeader
import app.securevault.ui.components.iconFor

/**
 * The vault.
 *
 * Two modes in one screen. With an empty search box it is a browsable home: favourites, recently
 * used, folders, then everything. Type anything and it collapses to a flat result list, because a
 * person searching wants results, not sections to scroll past.
 *
 * Search runs against the in-memory index built at unlock, which excludes secret fields -- so the
 * search box can never be used as an oracle for a password.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun VaultScreen(
    viewModel: VaultViewModel,
    onOpenItem: (VaultItem) -> Unit,
    onOpenFolders: () -> Unit,
    onOpenTags: () -> Unit,
    onOpenFolder: (String) -> Unit,
    onCreate: (ItemType) -> Unit
) {
    val filter by viewModel.filter.collectAsState()
    val visible by viewModel.visibleItems.collectAsState()
    val folders by viewModel.folders.collectAsState()

    var showAddSheet by remember { mutableStateOf(false) }
    val searching = filter.query.isNotBlank() || filter.type != null || filter.favoritesOnly

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Vault") },
                actions = {
                    IconButton(onClick = onOpenFolders) {
                        Icon(Icons.Filled.Folder, contentDescription = "Folders")
                    }
                    IconButton(onClick = onOpenTags) {
                        Icon(Icons.Filled.Sell, contentDescription = "Tags")
                    }
                    IconButton(onClick = { viewModel.lockNow() }) {
                        Icon(Icons.Filled.Lock, contentDescription = "Lock vault now")
                    }
                }
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { showAddSheet = true },
                icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                text = { Text("Add") }
            )
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            OutlinedTextField(
                value = filter.query,
                onValueChange = { query -> viewModel.setFilter { it.copy(query = query) } },
                placeholder = { Text("Search your vault") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                trailingIcon = {
                    if (filter.query.isNotEmpty()) {
                        TextButton(onClick = { viewModel.setFilter { it.copy(query = "") } }) {
                            Text("Clear")
                        }
                    }
                },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp)
            )

            TypeFilters(
                selected = filter.type,
                favoritesOnly = filter.favoritesOnly,
                counts = viewModel.countsByType(),
                onSelectType = { type ->
                    viewModel.setFilter { it.copy(type = type, favoritesOnly = false) }
                },
                onSelectFavorites = {
                    viewModel.setFilter { it.copy(favoritesOnly = !it.favoritesOnly, type = null) }
                }
            )

            when {
                viewModel.totalItems() == 0 -> EmptyState(
                    icon = Icons.Filled.Lock,
                    title = "Your vault is empty",
                    body = "Add your first login, or bring your passwords across from another " +
                        "manager using Settings, Import from CSV.",
                    actionLabel = "Add an item",
                    onAction = { showAddSheet = true }
                )

                searching && visible.isEmpty() -> EmptyState(
                    icon = Icons.Filled.Search,
                    title = "Nothing matches",
                    body = "Search looks at names, usernames, websites, tags and folders. " +
                        "It deliberately does not look inside passwords or codes.",
                    actionLabel = "Clear filters",
                    onAction = {
                        viewModel.setFilter { it.copy(query = "", type = null, favoritesOnly = false) }
                    }
                )

                searching -> LazyColumn(Modifier.fillMaxSize()) {
                    item {
                        SectionHeader("${visible.size} ${if (visible.size == 1) "result" else "results"}")
                    }
                    items(visible, key = { it.id }) { item ->
                        ItemRow(
                            item = item,
                            onOpen = { onOpenItem(item) },
                            onToggleFavorite = { viewModel.toggleFavorite(item) }
                        )
                    }
                    item { Spacer(Modifier.height(88.dp)) }
                }

                else -> BrowseList(
                    viewModel = viewModel,
                    folders = folders,
                    all = visible,
                    onOpenItem = onOpenItem,
                    onOpenFolder = onOpenFolder
                )
            }
        }
    }

    if (showAddSheet) {
        ModalBottomSheet(
            onDismissRequest = { showAddSheet = false },
            sheetState = rememberModalBottomSheetState()
        ) {
            AddItemSheet(
                onPick = { type ->
                    showAddSheet = false
                    onCreate(type)
                }
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TypeFilters(
    selected: ItemType?,
    favoritesOnly: Boolean,
    counts: Map<ItemType, Int>,
    onSelectType: (ItemType?) -> Unit,
    onSelectFavorites: () -> Unit
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        FilterChip(
            selected = selected == null && !favoritesOnly,
            onClick = { onSelectType(null) },
            label = { Text("All") }
        )
        FilterChip(
            selected = favoritesOnly,
            onClick = onSelectFavorites,
            label = { Text("Favourites") }
        )
        // Only types actually present, so the row does not become a wall of empty categories.
        ItemType.entries.filter { counts.getOrDefault(it, 0) > 0 }.forEach { type ->
            FilterChip(
                selected = selected == type,
                onClick = { onSelectType(if (selected == type) null else type) },
                label = { Text("${type.displayName} ${counts[type]}") }
            )
        }
    }
}

@Composable
private fun BrowseList(
    viewModel: VaultViewModel,
    folders: List<app.securevault.core.model.Folder>,
    all: List<VaultItem>,
    onOpenItem: (VaultItem) -> Unit,
    onOpenFolder: (String) -> Unit
) {
    val favorites = remember(all) { viewModel.favorites() }
    val recent = remember(all) { viewModel.recentlyUsed() }

    LazyColumn(Modifier.fillMaxSize()) {
        if (favorites.isNotEmpty()) {
            item { SectionHeader("Favourites") }
            items(favorites, key = { "fav-${it.id}" }) { item ->
                ItemRow(item, onOpen = { onOpenItem(item) },
                    onToggleFavorite = { viewModel.toggleFavorite(item) })
            }
        }

        if (recent.isNotEmpty()) {
            item { SectionHeader("Recently used") }
            items(recent, key = { "recent-${it.id}" }) { item ->
                ItemRow(item, onOpen = { onOpenItem(item) })
            }
        }

        if (folders.isNotEmpty()) {
            item { SectionHeader("Folders") }
            items(folders, key = { "folder-${it.id}" }) { folder ->
                val count = all.count { it.folderId == folder.id }
                ListItem(
                    headlineContent = { Text(folder.name) },
                    supportingContent = { Text("$count ${if (count == 1) "item" else "items"}") },
                    leadingContent = { Icon(Icons.Filled.Folder, contentDescription = null) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onOpenFolder(folder.id) }
                )
            }
        }

        item { SectionHeader("All items (${all.size})") }
        items(all, key = { it.id }) { item ->
            ItemRow(item, onOpen = { onOpenItem(item) },
                onToggleFavorite = { viewModel.toggleFavorite(item) })
        }
        item { Spacer(Modifier.height(88.dp)) }
    }
}

/** The + Add sheet. Passkeys are absent on purpose -- the provider is not implemented. */
@Composable
fun AddItemSheet(onPick: (ItemType) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(bottom = 32.dp)) {
        Text(
            "Add to your vault",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp)
        )
        ItemSchema.CREATABLE.forEach { type ->
            ListItem(
                headlineContent = { Text(type.displayName) },
                supportingContent = { Text(ItemSchema.titleHintFor(type)) },
                leadingContent = { Icon(iconFor(type), contentDescription = null) },
                // A whole row is a large, forgiving touch target; a text link is not.
                modifier = Modifier.fillMaxWidth().clickable { onPick(type) }
            )
        }
    }
}
