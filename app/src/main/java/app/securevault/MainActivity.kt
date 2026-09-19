package app.securevault

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.viewmodel.compose.viewModel
import app.securevault.di.ServiceLocator
import app.securevault.ui.AppRoot
import app.securevault.ui.VaultViewModel
import app.securevault.ui.theme.SecureVaultTheme

/**
 * The app's own entry point.
 *
 * It deliberately has no autofill responsibilities. The autofill unlock and save flows need to
 * return a result to the platform, and setResult on a singleTask activity does not reliably reach
 * the caller, so those live in AutofillAuthActivity and AutofillSaveActivity instead. This class
 * used to declare extras for them that nothing ever read.
 */
class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val viewModel: VaultViewModel = viewModel(factory = VaultViewModel.factory(application))
            val settings by viewModel.settings.collectAsState()
            SecureVaultTheme(theme = settings.theme) {
                AppRoot(viewModel = viewModel)
            }
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        ServiceLocator.autoLock(application).onUserInteraction()
    }
}
