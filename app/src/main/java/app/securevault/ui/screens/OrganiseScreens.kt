package app.securevault.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Sell
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.securevault.core.model.Folder
import app.securevault.core.model.VaultItem
import app.securevault.ui.VaultViewModel
import app.securevault.ui.components.EmptyState
import app.securevault.ui.components.ItemRow
import app.securevault.ui.components.InfoCard

/** Create, rename, delete folders. Deleting one never deletes what was inside it. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FoldersScreen(
    viewModel: VaultViewModel,
    onBack: () -> Unit,
    onOpenFolder: (String) -> Unit
) {
    val folders by viewModel.folders.collectAsState()
    val items by viewModel.visibleItems.collectAsState()

    var editing by remember { mutableStateOf<Folder?>(null) }
    var creating by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf<Folder?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Folders") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { creating = true }) {
                Icon(Icons.Filled.Add, contentDescription = "New folder")
            }
        }
    ) { padding ->
        if (folders.isEmpty()) {
            Column(Modifier.fillMaxSize().padding(padding)) {
                EmptyState(
                    icon = Icons.Filled.Folder,
                    title = "No folders yet",
                    body = "Folders are a way to group items. They are stored inside the encrypted " +
                        "payload, so folder names are not readable from the database file.",
                    actionLabel = "Create a folder",
                    onAction = { creating = true }
                )
            }
        } else {
            LazyColumn(Modifier.fillMaxSize().padding(padding)) {
                items(folders, key = { it.id }) { folder ->
                    val count = items.count { it.folderId == folder.id }
                    ListItem(
                        headlineContent = { Text(folder.name) },
                        supportingContent = { Text("$count ${if (count == 1) "item" else "items"}") },
                        leadingContent = { Icon(Icons.Filled.Folder, contentDescription = null) },
                        trailingContent = {
                            Row {
                                IconButton(onClick = { editing = folder }) {
                                    Icon(Icons.Filled.Edit, contentDescription = "Rename ${folder.name}")
                                }
                                IconButton(onClick = { deleting = folder }) {
                                    Icon(Icons.Filled.Delete, contentDescription = "Delete ${folder.name}")
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth().clickable { onOpenFolder(folder.id) }
                    )
                }
            }
        }
    }

    if (creating) {
        NameDialog(
            title = "New folder",
            initial = "",
            onDismiss = { creating = false },
            onConfirm = { name ->
                viewModel.saveFolder(Folder(name = name))
                creating = false
            }
        )
    }

    editing?.let { folder ->
        NameDialog(
            title = "Rename folder",
            initial = folder.name,
            onDismiss = { editing = null },
            onConfirm = { name ->
                viewModel.saveFolder(folder.copy(name = name))
                editing = null
            }
        )
    }

    deleting?.let { folder ->
        DeleteFolderDialog(
            folder = folder,
            otherFolders = folders.filter { it.id != folder.id },
            itemCount = items.count { it.folderId == folder.id },
            onDismiss = { deleting = null },
            onConfirm = { moveTo ->
                viewModel.deleteFolder(folder.id, moveTo)
                deleting = null
            }
        )
    }
}

@Composable
private fun DeleteFolderDialog(
    folder: Folder,
    otherFolders: List<Folder>,
    itemCount: Int,
    onDismiss: () -> Unit,
    onConfirm: (String?) -> Unit
) {
    var moveTo by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Delete \"${folder.name}\"?") },
        text = {
            Column {
                Text(
                    if (itemCount == 0) "This folder is empty."
                    else "The $itemCount ${if (itemCount == 1) "item" else "items"} in it will be " +
                        "kept. Choose where they should go."
                )
                if (itemCount > 0) {
                    FolderChoice(
                        options = otherFolders,
                        selected = moveTo,
                        onSelect = { moveTo = it }
                    )
                }
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(moveTo) }) { Text("Delete folder") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun FolderChoice(options: List<Folder>, selected: String?, onSelect: (String?) -> Unit) {
    FlowRow(
        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        FilterChip(
            selected = selected == null,
            onClick = { onSelect(null) },
            label = { Text("Leave unfiled") }
        )
        options.forEach { folder ->
            FilterChip(
                selected = selected == folder.id,
                onClick = { onSelect(folder.id) },
                label = { Text(folder.name) }
            )
        }
    }
}

/** The contents of one folder. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FolderContentsScreen(
    viewModel: VaultViewModel,
    folderId: String,
    onBack: () -> Unit,
    onOpenItem: (VaultItem) -> Unit
) {
    val folder = viewModel.folderById(folderId)
    val contents = viewModel.itemsInFolder(folderId)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(folder?.name ?: "Folder") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        if (contents.isEmpty()) {
            Column(Modifier.fillMaxSize().padding(padding)) {
                EmptyState(
                    icon = Icons.Filled.Folder,
                    title = "Nothing filed here yet",
                    body = "Open an item and set its folder to move it in."
                )
            }
        } else {
            LazyColumn(Modifier.fillMaxSize().padding(padding)) {
                items(contents, key = { it.id }) { item ->
                    ItemRow(
                        item = item,
                        onOpen = { onOpenItem(item) },
                        onToggleFavorite = { viewModel.toggleFavorite(item) }
                    )
                }
            }
        }
    }
}

/** Rename, delete and filter by tag. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TagsScreen(
    viewModel: VaultViewModel,
    onBack: () -> Unit,
    onFilterByTag: (String) -> Unit
) {
    val items by viewModel.visibleItems.collectAsState()
    val tags = remember(items) { viewModel.allTags() }
    var renaming by remember { mutableStateOf<String?>(null) }
    var deleting by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Tags") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        if (tags.isEmpty()) {
            Column(Modifier.fillMaxSize().padding(padding)) {
                EmptyState(
                    icon = Icons.Filled.Sell,
                    title = "No tags yet",
                    body = "Add tags while editing an item. Unlike folders, an item can carry " +
                        "several tags at once."
                )
            }
        } else {
            LazyColumn(Modifier.fillMaxSize().padding(padding)) {
                item {
                    InfoCard(
                        "Tags live inside the encrypted payload, so renaming one rewrites every " +
                            "item that carries it.",
                        Modifier.padding(20.dp)
                    )
                }
                items(tags, key = { it }) { tag ->
                    val count = items.count { tag in it.payload.tags }
                    ListItem(
                        headlineContent = { Text(tag) },
                        supportingContent = { Text("$count ${if (count == 1) "item" else "items"}") },
                        leadingContent = { Icon(Icons.Filled.Sell, contentDescription = null) },
                        trailingContent = {
                            Row {
                                IconButton(onClick = { renaming = tag }) {
                                    Icon(Icons.Filled.Edit, contentDescription = "Rename $tag")
                                }
                                IconButton(onClick = { deleting = tag }) {
                                    Icon(Icons.Filled.Delete, contentDescription = "Remove $tag")
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth().clickable { onFilterByTag(tag) }
                    )
                }
            }
        }
    }

    renaming?.let { tag ->
        NameDialog(
            title = "Rename tag",
            initial = tag,
            onDismiss = { renaming = null },
            onConfirm = { viewModel.renameTag(tag, it); renaming = null }
        )
    }

    deleting?.let { tag ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text("Remove \"$tag\"?") },
            text = { Text("The tag is removed from every item. The items themselves are untouched.") },
            confirmButton = {
                TextButton(onClick = { viewModel.deleteTag(tag); deleting = null }) { Text("Remove tag") }
            },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text("Cancel") } }
        )
    }
}

@Composable
private fun NameDialog(
    title: String,
    initial: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit
) {
    var name by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(name.trim()) }, enabled = name.isNotBlank()) {
                Text("Save")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}
