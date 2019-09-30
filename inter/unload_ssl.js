Java.perform(function() {
    //========android 7+
    try{
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');

        ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
            var k = array_list.$new();
            return k;
        }
    }catch (e) {
        //console.log('universal '+e);
    }

    //========TrustManager Android < 7 detection
    // ref: https://gist.github.com/oleavr/3ca67a173ff7d207c6b8c3b0ca65a9d8
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var TrustManager = Java.registerClass({
        name: 'com.sensepost.test.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });
    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    try {
        SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
    } catch (err) {
        //console.log("[-] TrustManager Not Found");
    }

    /*======== HttpsURLConnection */
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier){
        return null;
    };
    HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory){
        return null;
    };
    HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier){
        
        return null;
    };

    /*======== webview */
    var WebViewClient = Java.use("android.webkit.WebViewClient");    
    WebViewClient.onReceivedSslError.implementation = function (webView,sslErrorHandler,sslError){
        sslErrorHandler.proceed();
        return ;
    };    
    WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function (a,b,c,d){
        return ;
    };    
    WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (){
        return ;
    };
    

    /*======== okhttp3 */
    try {
        var CertificatePinner = Java.use("okhttp3.g");
        CertificatePinner.a.overload('java.lang.String', 'java.util.List').implementation = function(p0, p1){return;};
    } catch (e) {
        //console.log('okhttp3 '+e);
    }

    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            
        };
    } catch (err) {
        //console.log("[-] OkHTTP 3.x Not Found")
    }

}, 0);