package app.securevault.desktop.platform

/**
 * What this Ubuntu session can and cannot do about screen capture.
 *
 * ## The finding, stated plainly: there is nothing to implement
 *
 * Android's `FLAG_SECURE` asks the compositor to exclude a window from screenshots, the recents
 * thumbnail and screen recording. **Linux exposes no equivalent to an application**, and none of
 * the following would work:
 *
 *  - **X11 has no such mechanism at all.** Any client connected to the display can read any
 *    window's pixels with `XGetImage`, and no window property, hint or atom opts out. This is not
 *    a gap in a particular desktop environment; it is how the X protocol works. `java.awt.Robot`
 *    is itself an example of a client doing exactly this.
 *  - **Wayland is better, but not controllable by the application.** Clients cannot read each
 *    other's buffers, and capture is mediated by the compositor through xdg-desktop-portal, which
 *    normally prompts. But there is no per-window "exclude me from capture" API a client can call,
 *    and once a screencast is authorised it records this window along with everything else.
 *  - **AWT and Compose Desktop expose nothing.** There is no counterpart to Windows'
 *    `SetWindowDisplayAffinity`. Setting some custom window property and calling it protection
 *    would be exactly the fake security this project has refused elsewhere.
 *
 * There is one extra wrinkle worth telling the user about: **the JDK has no Wayland AWT backend**,
 * so a Compose Desktop application on a Wayland session runs through XWayland. Among XWayland
 * clients the X11 situation applies again — so "I am on Wayland" is weaker protection here than it
 * would be for a native Wayland application.
 *
 * Adding an X11 or Wayland native dependency would not change any of this. The conclusion is to
 * describe the situation accurately and point at the mitigations that are real: locking on focus
 * loss, short auto-lock, and secrets masked until revealed.
 */
object ScreenCapture {

    enum class Session { X11, WAYLAND_VIA_XWAYLAND, WAYLAND_NATIVE, UNKNOWN }

    data class Status(val session: Session, val summary: String, val detail: String)

    fun detect(): Status {
        val sessionType = System.getenv("XDG_SESSION_TYPE")?.lowercase().orEmpty()
        val wayland = !System.getenv("WAYLAND_DISPLAY").isNullOrBlank()
        val x11Display = !System.getenv("DISPLAY").isNullOrBlank()

        val session = when {
            // A Wayland session with an X display present means this JVM is on XWayland, because
            // AWT has no Wayland backend to use.
            wayland && x11Display -> Session.WAYLAND_VIA_XWAYLAND
            wayland -> Session.WAYLAND_NATIVE
            sessionType == "x11" || x11Display -> Session.X11
            else -> Session.UNKNOWN
        }

        return Status(
            session = session,
            summary = when (session) {
                Session.X11 ->
                    "X11 session — any application on this display can capture this window."
                Session.WAYLAND_VIA_XWAYLAND ->
                    "Wayland session, but SecureVault runs through XWayland — other XWayland " +
                        "applications can capture this window."
                Session.WAYLAND_NATIVE ->
                    "Wayland session — capture is mediated by the compositor, but SecureVault " +
                        "cannot exclude itself from an authorised screen recording."
                Session.UNKNOWN ->
                    "Display server could not be identified — assume this window can be captured."
            },
            detail = COMMON_DETAIL
        )
    }

    private const val COMMON_DETAIL =
        "Linux provides no universal equivalent to Android's FLAG_SECURE. On Android, SecureVault " +
            "asks the system to exclude its window from screenshots, screen recording and the " +
            "recents thumbnail. No such request exists on X11 or Wayland, so screenshot and " +
            "screen-recording prevention cannot be guaranteed on Linux and SecureVault does not " +
            "claim it.\n\n" +
            "What does help, and is already available: lock when the window loses focus, a short " +
            "auto-lock timeout, and secrets staying masked until you reveal them."
}
