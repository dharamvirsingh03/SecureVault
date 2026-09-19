package app.securevault.data.repo

import app.securevault.core.model.Fields
import app.securevault.core.model.Folder
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.core.vault.VaultSession
import app.securevault.feature.autofill.AutofillDomainMatcher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class SortOrder { TITLE, RECENTLY_MODIFIED, RECENTLY_USED, FAVORITES_FIRST }

data class VaultFilter(
    val query: String = "",
    val type: ItemType? = null,
    val folderId: String? = null,
    val tag: String? = null,
    val favoritesOnly: Boolean = false,
    val sort: SortOrder = SortOrder.TITLE
)

/**
 * Search over an encrypted vault, done the only way that does not leak: decrypt once into memory
 * while unlocked, search there, and drop everything on lock.
 *
 * There is deliberately no plaintext search table on disk. An index outside the vault would
 * recreate exactly the data the encryption exists to hide, and would survive locking.
 *
 * Searchable text never includes passwords, card numbers, CVVs or other secret fields -- matching
 * on a secret would turn the search box into an oracle for it.
 */
class VaultIndex {

    private val itemsState = MutableStateFlow<List<VaultItem>>(emptyList())
    private val foldersState = MutableStateFlow<List<Folder>>(emptyList())
    private var searchable: Map<String, String> = emptyMap()

    val items: StateFlow<List<VaultItem>> = itemsState.asStateFlow()
    val folders: StateFlow<List<Folder>> = foldersState.asStateFlow()

    suspend fun refresh(session: VaultSession, repository: ItemRepository) {
        val loaded = repository.loadAll(session)
        itemsState.value = loaded
        foldersState.value = repository.loadFolders(session)
        searchable = loaded.associate { it.id to buildSearchableText(it) }
    }

    /** Called on lock. Drops decrypted content and the derived search text. */
    fun clear() {
        itemsState.value = emptyList()
        foldersState.value = emptyList()
        searchable = emptyMap()
    }

    fun allTags(): List<String> =
        itemsState.value.flatMap { it.payload.tags }.distinct().sorted()

    fun query(filter: VaultFilter): List<VaultItem> {
        val needle = filter.query.trim().lowercase()
        val result = itemsState.value.asSequence()
            .filter { filter.type == null || it.type == filter.type }
            .filter { filter.folderId == null || it.folderId == filter.folderId }
            .filter { filter.tag == null || it.payload.tags.contains(filter.tag) }
            .filter { !filter.favoritesOnly || it.favorite }
            .filter { needle.isEmpty() || searchable[it.id]?.contains(needle) == true }
            .toList()

        return when (filter.sort) {
            SortOrder.TITLE -> result.sortedBy { it.title.lowercase() }
            SortOrder.RECENTLY_MODIFIED -> result.sortedByDescending { it.updatedAt }
            SortOrder.RECENTLY_USED -> result.sortedByDescending { it.lastUsedAt ?: 0L }
            SortOrder.FAVORITES_FIRST ->
                result.sortedWith(compareByDescending<VaultItem> { it.favorite }.thenBy { it.title.lowercase() })
        }
    }

    fun recentlyUsed(limit: Int = 8): List<VaultItem> =
        itemsState.value.filter { it.lastUsedAt != null }.sortedByDescending { it.lastUsedAt }.take(limit)

    fun favorites(): List<VaultItem> = itemsState.value.filter { it.favorite }.sortedBy { it.title.lowercase() }

    /**
     * Used by the autofill service to find candidates for a web domain or package name.
     *
     * Matching is delegated to [AutofillDomainMatcher], which anchors on host boundaries. Anything
     * looser would offer a bank login to a lookalike domain, and the whole point of autofill as a
     * security feature is that it refuses to type a password into the wrong site.
     */
    fun matchesFor(domain: String): List<VaultItem> {
        if (domain.isBlank()) return emptyList()
        return itemsState.value.filter { item ->
            item.type == ItemType.LOGIN && AutofillDomainMatcher.matches(item.url, domain)
        }
    }

    private fun buildSearchableText(item: VaultItem): String = buildString {
        append(item.title).append(' ')
        append(item.type.displayName).append(' ')
        item.payload.fields
            .filterKeys { it !in Fields.SECRET_FIELDS }
            .values.forEach { append(it).append(' ') }
        item.payload.tags.forEach { append(it).append(' ') }
        item.payload.customFields
            .filter { it.kind != app.securevault.core.model.FieldKind.HIDDEN }
            .forEach { append(it.name).append(' ').append(it.value).append(' ') }
    }.lowercase()
}
