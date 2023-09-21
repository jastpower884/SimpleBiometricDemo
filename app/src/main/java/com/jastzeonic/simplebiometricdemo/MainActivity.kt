package com.jastzeonic.simplebiometricdemo

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.jastzeonic.simplebiometricdemo.ui.theme.SimpleBiometricDemoTheme
import java.nio.charset.Charset
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

private const val KEY_NAME = "KEY_NAME"

class MainActivity : FragmentActivity() {

    private lateinit var executor: Executor
    private val contentText: MutableState<ByteArray?> = mutableStateOf("Hello".toByteArray())
    private var iv: MutableState<ByteArray?> = mutableStateOf(null)

    private lateinit var biometricPrompt: BiometricPrompt
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        executor = ContextCompat.getMainExecutor(this)
        val activity: FragmentActivity = this
        biometricPrompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(
                        activity.applicationContext,
                        "error",
                        Toast.LENGTH_SHORT
                    ).show()
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)

                    if (iv.value == null) {
                        val encryptedInfo = result.cryptoObject?.cipher?.doFinal(String(contentText.value ?: byteArrayOf()).toByteArray(Charset.defaultCharset()))
                        contentText.value = encryptedInfo
                        iv.value = result.cryptoObject?.cipher?.iv
                    } else {
                        val decryptedInfo: ByteArray? = result.cryptoObject?.cipher?.doFinal(contentText.value)
                        contentText.value = decryptedInfo
                        iv.value = null
                    }

                    Toast.makeText(activity.applicationContext, "succeeded!", Toast.LENGTH_LONG).show()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(
                        activity.applicationContext, "failed", Toast.LENGTH_LONG
                    ).show()
                }
            }
        )


        setContent {
            SimpleBiometricDemoTheme {
                // A surface container using the 'background' color from the theme
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    ButtonZone()
                }
            }
        }
    }

    @Composable
    private fun ButtonZone() {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.fillMaxSize()
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally
            ) {

                Text(text = String(contentText.value ?: byteArrayOf()))

                Button(
                    enabled = (iv.value?.isEmpty() ?: true),
                    onClick = { encryption() }) {
                    Text("Encryption")

                }
                Button(
                    enabled = iv.value?.isNotEmpty() == true,
                    onClick = { decryption() }) {
                    Text("Decryption")

                }
            }

        }
    }

    private fun encryption() {

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("title")
            .setSubtitle("subtitle")
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()


        val cipher = getCipher()
        val secretKey = try {
            getSecretKey()
        } catch (ex: Exception) {
            generateSecretKey(
                KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(true)
                    // Invalidate the keys if the user has registered a new biometric
                    // credential, such as a new fingerprint. Can call this method only
                    // on Android 7.0 (API level 24) or higher. The variable
                    // "invalidatedByBiometricEnrollment" is true by default.
                    .setInvalidatedByBiometricEnrollment(true)
                    .build()
            )

            getSecretKey()
        }

        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        BiometricPrompt.CryptoObject(cipher)
    }

    private fun decryption() {

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("title")
            .setSubtitle("subtitle")
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()

        val cipher = getCipher()
        val secretKey = try {
            getSecretKey()
        } catch (ex: Exception) {
            generateSecretKey(
                KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(true)
                    // Invalidate the keys if the user has registered a new biometric
                    // credential, such as a new fingerprint. Can call this method only
                    // on Android 7.0 (API level 24) or higher. The variable
                    // "invalidatedByBiometricEnrollment" is true by default.
                    .setInvalidatedByBiometricEnrollment(true)
                    .build()
            )

            getSecretKey()
        }

        cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv.value))
        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        BiometricPrompt.CryptoObject(cipher)
    }

    private fun getCipher(): Cipher {
        return Cipher.getInstance(
            KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7
        )
    }

    private fun generateSecretKey(keyGenParameterSpec: KeyGenParameterSpec) {

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }

    private fun getSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")

        // Before the keystore can be accessed, it must be loaded.
        keyStore.load(null)
        return keyStore.getKey(KEY_NAME, null) as SecretKey
    }


}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    SimpleBiometricDemoTheme {
    }
}