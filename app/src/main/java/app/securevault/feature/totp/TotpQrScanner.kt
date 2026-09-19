package app.securevault.feature.totp

import android.Manifest
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors

/**
 * Offline QR enrolment for TOTP secrets.
 *
 * Reports the raw decoded text. Parsing, previewing and confirming happen in the editor, so the
 * user sees what a code contains before it is accepted -- and so an unreadable code produces an
 * error rather than silence.
 *
 * The camera frame is decoded on device by the bundled barcode scanner. No image is uploaded, no
 * image is written to disk, and the decoded otpauth:// URI goes straight into the encrypted item
 * without passing through the clipboard or a log.
 */
@SuppressLint("UnsafeOptInUsageError")
@Composable
fun TotpQrScanner(onScanned: (String) -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    val scanner = remember { BarcodeScanning.getClient() }

    // Camera permission is requested here, at the moment the user chose to scan -- never at
    // startup. A password manager that asks for the camera on first launch has not earned it yet.
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    var denied by remember { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { result ->
        granted = result
        denied = !result
    }

    LaunchedEffect(Unit) {
        if (!granted) permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    if (!granted) {
        Column(Modifier.fillMaxSize().padding(24.dp)) {
            Text(
                if (denied) {
                    "SecureVault needs the camera to read a QR code. Nothing is uploaded and no " +
                        "image is saved. You can enter the setup key by hand instead."
                } else {
                    "Waiting for camera permission."
                },
                style = MaterialTheme.typography.bodyMedium
            )
            TextButton(onClick = onCancel) { Text("Enter the code by hand instead") }
        }
        return
    }

    Column(Modifier.fillMaxSize()) {
        Box(Modifier.weight(1f)) {
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx ->
                    val previewView = PreviewView(ctx)
                    val providerFuture = ProcessCameraProvider.getInstance(ctx)
                    providerFuture.addListener({
                        val provider = providerFuture.get()
                        val preview = Preview.Builder().build()
                            .also { it.surfaceProvider = previewView.surfaceProvider }

                        val analysis = ImageAnalysis.Builder()
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()

                        analysis.setAnalyzer(executor) { imageProxy ->
                            val mediaImage = imageProxy.image
                            if (mediaImage == null) {
                                imageProxy.close()
                                return@setAnalyzer
                            }
                            val input = InputImage.fromMediaImage(
                                mediaImage, imageProxy.imageInfo.rotationDegrees
                            )
                            scanner.process(input)
                                .addOnSuccessListener { codes ->
                                    // The raw value is handed up unparsed. Deciding whether a code
                                    // is a usable otpauth:// URI is the caller's job, so a
                                    // malformed or unrelated QR produces a visible error instead
                                    // of the camera appearing to ignore it.
                                    codes.firstOrNull { it.valueType == Barcode.TYPE_TEXT || it.rawValue != null }
                                        ?.rawValue
                                        ?.let(onScanned)
                                }
                                .addOnCompleteListener { imageProxy.close() }
                        }

                        provider.unbindAll()
                        provider.bindToLifecycle(
                            lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis
                        )
                    }, ContextCompat.getMainExecutor(ctx))
                    previewView
                }
            )
        }
        Column(Modifier.padding(20.dp)) {
            Text(
                "Point the camera at the QR code your account shows when it offers an authenticator app.",
                style = MaterialTheme.typography.bodyMedium
            )
            TextButton(onClick = onCancel) { Text("Enter the code by hand instead") }
        }
    }
}
