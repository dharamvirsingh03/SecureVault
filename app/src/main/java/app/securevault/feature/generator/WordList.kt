package app.securevault.feature.generator

import android.content.Context

/**
 * Android's [WordSource]: the EFF list shipped as an asset.
 *
 * Parsing and the "is this a full diceware list" judgement live in :core, so a list that is
 * accepted on Android is accepted identically on the desktop.
 */
class AssetWordSource(private val context: Context) : WordSource {

    override fun words(): List<String> = runCatching {
        context.assets.open(ASSET).bufferedReader().use { WordLists.parse(it.readText()) }
    }.getOrNull()?.takeIf { it.isNotEmpty() } ?: FALLBACK

    companion object {
        private const val ASSET = "eff_large_wordlist.txt"
    }
}

/**
 * A deliberately small fallback so the generator always works.
 *
 * The generator reports entropy from the list actually in use, so this under-promises rather than
 * over-promises. It is not a substitute for shipping the EFF list.
 */
internal val FALLBACK: List<String> = listOf(
    "abacus", "anchor", "antique", "autumn", "badge", "bamboo", "banjo", "basket", "beacon",
    "bison", "blanket", "blossom", "bobcat", "bonus", "bramble", "bridge", "bucket", "bundle",
    "cabin", "cactus", "canyon", "cargo", "carrot", "cedar", "chisel", "cinder", "clover",
    "cobalt", "comet", "compass", "copper", "coral", "cotton", "cradle", "crimson", "crystal",
    "dagger", "dahlia", "damson", "dapple", "denim", "dolphin", "domino", "drapery", "driftwood",
    "ember", "emerald", "engine", "escape", "fable", "falcon", "fennel", "fiddle", "flint",
    "forest", "fossil", "fountain", "gadget", "gallop", "garnet", "gazelle", "ginger", "glacier",
    "granite", "gravel", "grotto", "gusto", "hammock", "harbour", "harvest", "hazel", "hearth",
    "helmet", "hollow", "hornet", "icicle", "indigo", "ingot", "island", "ivory", "jasmine",
    "jigsaw", "jubilee", "juniper", "kettle", "keystone", "lantern", "lattice", "lavender",
    "ledger", "lichen", "lilac", "lobster", "lumber", "magnet", "mahogany", "mallet", "maple",
    "marble", "marigold", "meadow", "mercury", "mineral", "mitten", "monsoon", "mosaic", "nectar",
    "nimbus", "nomad", "nutmeg", "obsidian", "olive", "onyx", "orbit", "orchard", "otter",
    "paddle", "pantry", "papaya", "parsley", "pebble", "pelican", "pepper", "pewter", "pickaxe",
    "pigment", "pillar", "pistachio", "plateau", "pollen", "poplar", "prairie", "pumpkin",
    "quarry", "quartz", "quiver", "radish", "rafter", "rampart", "ravine", "rhubarb", "ribbon",
    "rivet", "rosemary", "rudder", "saffron", "sapling", "satchel", "scallop", "sequoia",
    "shale", "sherbet", "shovel", "silo", "sparrow", "spindle", "sprocket", "starling", "stencil",
    "sundial", "tamarind", "tangerine", "teapot", "thicket", "thimble", "thistle", "timber",
    "tinder", "toffee", "trellis", "trombone", "trowel", "truffle", "tundra", "turnip", "vanilla",
    "velvet", "vinegar", "violet", "walnut", "whisker", "willow", "window", "wombat", "yarrow"
)
