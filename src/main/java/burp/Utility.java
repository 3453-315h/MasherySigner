package burp;

import com.google.common.base.Strings;
import com.google.common.hash.Hashing;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utility {

    public static byte[] signRequest(IHttpRequestResponse messageInfo, IExtensionHelpers helpers, String apiKey, String apiSecret) throws Exception {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        byte[] request = messageInfo.getRequest();

        // Get our current parameters
        List<IParameter> params = requestInfo.getParameters();

        // Remove previous signature and API key
        request = helpers.removeParameter(request, helpers.buildParameter("api_key", "", IParameter.PARAM_URL));
        request = helpers.removeParameter(request, helpers.buildParameter("sig", "", IParameter.PARAM_URL));

        // Generate a new signature
        StringBuilder sb = new StringBuilder();
        sb.append(apiKey);
        sb.append(apiSecret);
        sb.append(System.currentTimeMillis()/1000L);
        String sig = Hashing.sha256().hashString(sb.toString(), StandardCharsets.UTF_8).toString();

        // Add the new params to the array
        request = helpers.addParameter(request, helpers.buildParameter("api_key", apiKey, IParameter.PARAM_URL));
        request = helpers.addParameter(request, helpers.buildParameter("sig", sig, IParameter.PARAM_URL));
        return request;
    }

    private static byte[] HmacSHA256(String data, byte[] key) throws Exception {
        String algorithm="HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("UTF8"));
    }

    private static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
        byte[] kDate = HmacSHA256(dateStamp, kSecret);
        byte[] kRegion = HmacSHA256(regionName, kDate);
        byte[] kService = HmacSHA256(serviceName, kRegion);
        return HmacSHA256("aws4_request", kService);
    }

    private static String getSignedHeaders(String authHeader){

        String signedHeaders = "";

        Pattern pattern = Pattern.compile("SignedHeaders=(.*?),");

        Matcher matcher = pattern.matcher(authHeader);
        if (matcher.find()){
            signedHeaders = matcher.group(1);
        }

        return  signedHeaders;

    }
}
