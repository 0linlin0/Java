package burp;


import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
 
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
 
public class NetStateUtil {
	public Object[] result = null;
	public String fulldomain;
	public NetStateUtil(int i,String fulldomain) {
    	this.fulldomain=fulldomain;
	}
    static HostnameVerifier hv = new HostnameVerifier() {  
        public boolean verify(String urlHostName, SSLSession session) {  
            return true;  
        }  
    };  
    public Object[] getresult() {
    	String remoteInetAddr1="http://"+fulldomain;
    	String remoteInetAddr2="https://"+fulldomain;
    	connectingAddress(remoteInetAddr1);
    	connectingAddress(remoteInetAddr2);
    	return result;
    }
    public void connectingAddress(String remoteInetAddr){
    	Object[] theresult=new Object[3];
        boolean flag=false;
        String tempUrl=remoteInetAddr.substring(0, 5);//取出地址前5位
        if(tempUrl.contains("http")){//判断传过来的地址中是否有http
            if(tempUrl.equals("https")){//判断服务器是否是https协议
                try {
                    trustAllHttpsCertificates();//当协议是https时
                } catch (Exception e) {
                    e.printStackTrace();
                }  
                HttpsURLConnection.setDefaultHostnameVerifier(hv);//当协议是https时
            }
            flag=isConnServerByHttp(remoteInetAddr);
        }else{//传过来的是IP地址
            flag=isReachable(remoteInetAddr);
        }
        if(flag){
        	theresult[0]= fulldomain;
        	theresult[1]= "可访问";
        	theresult[2]= remoteInetAddr;
        }else{
        	theresult[0]= fulldomain;
        	theresult[1]= "false";
        	theresult[2]= "空";
        }
        
        result=theresult;
    }
    /**
     * 传入需要连接的IP，返回是否连接成功
     *
     * @param remoteInetAddr
     * @return
     */
    public static boolean isReachable(String remoteInetAddr) {// IP地址是否可达，相当于Ping命令
        boolean reachable = false;
        try {
            InetAddress address = InetAddress.getByName(remoteInetAddr);
            reachable = address.isReachable(1500);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return reachable;
    }
 
    public static boolean isConnServerByHttp(String serverUrl) {// 服务器是否开启
        boolean connFlag = false;
        URL url;
        HttpURLConnection conn = null;
        try {
            url = new URL(serverUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3 * 1000);
            if (conn.getResponseCode() == 200) {// 如果连接成功则设置为true
                connFlag = true;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            conn.disconnect();
        }
        return connFlag;
    }
    /*以下是Https适用*/
    private static void trustAllHttpsCertificates() throws Exception {  
        javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[1];  
        javax.net.ssl.TrustManager tm = new miTM();  
        trustAllCerts[0] = tm;  
        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext  
                .getInstance("SSL");  
        sc.init(null, trustAllCerts, null);  
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc  
                .getSocketFactory());  
    }  
 
    static class miTM implements javax.net.ssl.TrustManager,  
            javax.net.ssl.X509TrustManager {  
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {  
            return null;  
        }  
 
        public boolean isServerTrusted(  
                java.security.cert.X509Certificate[] certs) {  
            return true;  
        }  
 
        public boolean isClientTrusted(  
                java.security.cert.X509Certificate[] certs) {  
            return true;  
        }  
 
        public void checkServerTrusted(  
                java.security.cert.X509Certificate[] certs, String authType)  
                throws java.security.cert.CertificateException {  
            return;  
        }  
 
        public void checkClientTrusted(  
                java.security.cert.X509Certificate[] certs, String authType)  
                throws java.security.cert.CertificateException {  
            return;  
        }  
    } 
//    public static Object[][] main(String[] args) {
////    	String domains[] = {"Jimmy","Gougou","Doggy"};  
////    	for (int i = 0; i < domains.length; i++) {
////        	NetStateUtil netStateUtil=new NetStateUtil(i,domains[i]+".baidu.com");
////        	netStateUtil.getresult();
////    	}
//    	return result;
//
//    }
}
    /*以上是Https适用*/

