package app.securevault.core.crypto

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets

/**
 * Helpers for handling key material without leaving avoidable copies on the heap.
 *
 * Honest limitation: the JVM can move and copy arrays during GC, and Android may page memory to
 * disk. Zeroing is best-effort defence in depth, not a guarantee. Never rely on it alone.
 */
object SecureBytes {

    fun zero(vararg arrays: ByteArray?) {
        for (a in arrays) a?.fill(0)
    }

    fun zeroChars(vararg arrays: CharArray?) {
        for (a in arrays) a?.fill('\u0000')
    }

    /** UTF-8 encodes without ever materialising an immutable String. */
    fun utf8(chars: CharArray): ByteArray {
        val encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars))
        val out = ByteArray(encoded.remaining())
        encoded.get(out)
        if (encoded.hasArray()) encoded.array().fill(0)
        return out
    }

    /** Constant-time comparison. Use for any comparison involving secret bytes. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(parts.sumOf { it.size })
        parts.forEach { buf.put(it) }
        return buf.array()
    }
}
