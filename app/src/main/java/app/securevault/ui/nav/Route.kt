package app.securevault.ui.nav

import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import app.securevault.core.model.ItemType

/**
 * Every place the app can be.
 *
 * A sealed hierarchy rather than `navigation-compose`, after weighing the audit's suggestion.
 * Two reasons, in order of importance:
 *
 *  1. **Routes here cannot carry a secret even by accident.** navigation-compose encodes
 *     arguments into a URL-like string that lands in the back stack, in saved instance state, and
 *     in logs when anything goes wrong. In a password manager that is a category of mistake worth
 *     designing out rather than remembering not to make. These routes hold UUIDs and enum values
 *     and nothing else, and the type system enforces it.
 *  2. The dependency version could not be resolved in this environment, and adding an unverifiable
 *     dependency to a build that already cannot be compiled makes the first real build harder to
 *     diagnose, not easier.
 *
 * What is given up: deep links and process-death restoration. Neither is wanted here. A password
 * manager should not be deep-linkable into an item, and after process death the correct state is
 * the lock screen, which is exactly where an empty back stack lands.
 */
sealed interface Route {

    /** Routes that sit at the bottom of the stack, one per bottom-navigation tab. */
    sealed interface Tab : Route

    data object Vault : Tab
    data object Generator : Tab
    data object Security : Tab
    data object Settings : Tab

    // --- vault ---------------------------------------------------------------------------
    // Search is not a route. It is the state of the Vault screen's own filter, which means a
    // search survives opening an item and coming back -- the behaviour people actually want --
    // without a query string ever entering a back stack.
    data class FolderContents(val folderId: String) : Route
    data object Folders : Route
    data object Tags : Route

    /** Only the id travels. The item itself is read from the unlocked vault in memory. */
    data class ItemDetail(val itemId: String) : Route

    /** [itemId] null means "create a new item of [type]". */
    data class ItemEditor(val itemId: String?, val type: ItemType) : Route

    // --- security ------------------------------------------------------------------------
    data class SecurityIssues(val category: IssueCategory) : Route

    // --- settings ------------------------------------------------------------------------
    data object Import : Route
    data object Export : Route
    data object Backup : Route
    data object Restore : Route
    data object Recovery : Route
    data object EmergencyKit : Route
    data object ChangePassword : Route
    data object DestroyVault : Route
}

enum class IssueCategory(val title: String) {
    WEAK("Weak passwords"),
    REUSED("Reused passwords"),
    OLD("Old passwords"),
    MISSING_2FA("Missing two-factor"),
    BREACHED("Found in a breach")
}

/**
 * A back stack, and nothing more.
 *
 * Tabs are roots: switching tabs resets to that tab's root rather than growing the stack, which is
 * what Android users expect from bottom navigation and keeps the stack shallow.
 */
class Navigator(initial: Route.Tab = Route.Vault) {

    private val stack = mutableStateListOf<Route>(initial)

    val current: Route get() = stack.last()

    val currentTab: Route.Tab get() = stack.first() as Route.Tab

    val canGoBack: Boolean get() = stack.size > 1

    fun push(route: Route) {
        if (stack.last() != route) stack.add(route)
    }

    /** @return false when there was nothing to pop, so the caller can let the system handle back. */
    fun pop(): Boolean {
        if (stack.size <= 1) return false
        stack.removeAt(stack.lastIndex)
        return true
    }

    fun popTo(route: Route) {
        val index = stack.indexOf(route)
        if (index >= 0) while (stack.lastIndex > index) stack.removeAt(stack.lastIndex)
    }

    fun selectTab(tab: Route.Tab) {
        stack.clear()
        stack.add(tab)
    }

    /**
     * Drops everything. Called when the vault locks -- an unlocked back stack containing an item
     * id is not sensitive in itself, but resuming into a detail screen after a lock would be
     * disorienting and would briefly render an empty shell where content used to be.
     */
    fun reset(tab: Route.Tab = Route.Vault) = selectTab(tab)
}

@Composable
fun rememberNavigator(): Navigator = remember { Navigator() }
