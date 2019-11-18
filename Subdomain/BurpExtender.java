package burp;

import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.JMenuItem;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;
import javax.swing.JFileChooser;
import javax.swing.ListModel;

import burp.NetStateUtil;

public class BurpExtender extends javax.swing.JFrame implements IBurpExtender, IHttpListener,ITab,IContextMenuFactory{

    public PrintWriter stdout;
    public IExtensionHelpers hps;
    public IBurpExtenderCallbacks cbs;
    
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JList jList2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JTable jTable1;
	private IContextMenuInvocation invocation;
	private JFileChooser jfc=new  JFileChooser(new File("."));
	public Object[][] result;
	public ArrayList dict;
	public String choseddomain;

	

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)         {

        callbacks.setExtensionName("linlintest");
        callbacks.registerContextMenuFactory(this);

        this.hps = callbacks.getHelpers();
        this.cbs = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        this.stdout.println("hello burp!");

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
            	jPanel1 = new javax.swing.JPanel();
                jScrollPane3 = new javax.swing.JScrollPane();
                jList2 = new javax.swing.JList();
                jButton1 = new javax.swing.JButton();
                jScrollPane1 = new javax.swing.JScrollPane();
                jTable1 = new javax.swing.JTable();
                jButton2 = new javax.swing.JButton();
                jButton3 = new javax.swing.JButton();

                setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

                jList2.setModel(new javax.swing.AbstractListModel() {
                    String[] strings = { };
                    public int getSize() { return strings.length; }
                    public Object getElementAt(int i) { return strings[i]; }
                });
                jScrollPane3.setViewportView(jList2);

                jButton1.setText("批量导入");
                jButton1.addMouseListener(new MouseAdapter() {

                    @Override
                    public void mouseClicked(MouseEvent e){//这里是具体功能实现代码 涉及到文件操作
                    	jfc.showOpenDialog(jPanel1);
                    	File file = jfc.getSelectedFile();
                    	Scanner scanner = null;
						try {
							scanner = new Scanner(file);
						} catch (FileNotFoundException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						ArrayList listarry = new ArrayList();
                        while(scanner.hasNextLine())
                        {

                            String str=scanner.nextLine();//逐行读取文件
    			    		listarry.add(str);
                        }
                        //把读取的数据存到文本框中
                        String[] listData=(String[]) listarry.toArray(new String[listarry.size()]);
                        jList2.setListData(listData);
                    }

                });

                jTable1.setModel(new javax.swing.table.DefaultTableModel(
                    new Object [][] {
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null},
                        {null, null, null}
                    },
                    new String [] {
                    	"域名", "是否存在", "url"
                    }
                ) {
                    Class[] types = new Class [] {
                        java.lang.String.class, java.lang.String.class, java.lang.String.class
                    };

                    public Class getColumnClass(int columnIndex) {
                        return types [columnIndex];
                    }
                });
                jScrollPane1.setViewportView(jTable1);

                jButton3.setText("start");
                jButton3.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e){
                    	ArrayList domainsarry = dict;
                    	String[] domains=(String[]) domainsarry.toArray(new String[domainsarry.size()]);
                    	Object[][] theresult=new Object[domains.length][3];
                    	for (int i = 0; i < domains.length; i++) {
                        	NetStateUtil netStateUtil=new NetStateUtil(i,domains[i]+"."+choseddomain);
                        	Object[] resultrow =netStateUtil.getresult();
                        	//String[] resultrow = {"aaa","bbb","ccc"};
                        	theresult[i][0]=resultrow[0];
                        	theresult[i][1]=resultrow[1];
                        	theresult[i][2]=resultrow[2];
                    	}
                    	result=theresult;
                    }

                });
                
                jList2.addListSelectionListener(new ListSelectionListener(){

					@Override
					public void valueChanged(ListSelectionEvent e) {
						// TODO Auto-generated method stub
						int[] indices = jList2.getSelectedIndices();
		                // 获取选项数据的 ListModel
		                ListModel<String> listModel = jList2.getModel();
		                // 输出选中的选项
		                choseddomain=listModel.getElementAt(indices[0]);
		                
		                jTable1.setModel(new javax.swing.table.DefaultTableModel(
		                		result,
		                        new String [] {
		                            "域名", "是否存在", "url"
		                        }
		                    ) {
		                        Class[] types = new Class [] {
		                            java.lang.String.class, java.lang.String.class, java.lang.String.class
		                        };

		                        public Class getColumnClass(int columnIndex) {
		                            return types [columnIndex];
		                        }
		                    });
					}});

                jButton2.setText("导入字典");
                jButton2.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e){
                    	jfc.showOpenDialog(jPanel1);
                    	File file = jfc.getSelectedFile();
                    	Scanner scanner = null;
						try {
							scanner = new Scanner(file);
						} catch (FileNotFoundException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						ArrayList listarry = new ArrayList();
                        while(scanner.hasNextLine())
                        {

                            String str=scanner.nextLine();
    			    		listarry.add(str);
                        }
                        //把读取的数据存到文本框中
                        dict=listarry;
                    }

                });
                

                javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
                jPanel1.setLayout(jPanel1Layout);
                jPanel1Layout.setHorizontalGroup(
                    jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 85, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jButton1))
                        .addGap(8, 8, 8)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                                .addComponent(jButton2)
                                .addGap(149, 149, 149)
                                .addComponent(jButton3)
                                .addGap(18, 18, 18))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 462, Short.MAX_VALUE)
                                .addContainerGap())))
                );
                jPanel1Layout.setVerticalGroup(
                    jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 253, Short.MAX_VALUE)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jButton1)
                            .addComponent(jButton2)
                            .addComponent(jButton3))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                );

                javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
                getContentPane().setLayout(layout);
                layout.setHorizontalGroup(
                    layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addContainerGap())
                );
                layout.setVerticalGroup(
                    layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addContainerGap())
                );

                
                // 设置自定义组件并添加标签
                cbs.customizeUiComponent(jPanel1);

                cbs.addSuiteTab(BurpExtender.this);
                
                ///aaa
            }
        });
    }
    
    // 实现 ITab 接口的 getTabCaption 方法
    public String getTabCaption() {
        return "linlin";
    }

    // 实现 ITab 接口的 getUiComponent 方法
    @Override
    public Component getUiComponent() {
        return jPanel1;
    }
    
    public static void main(String[] args) {

    }
    
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
    	if(invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_TARGET){
        	JMenuItem menuItem = new JMenuItem("获取子域");
        	IHttpRequestResponse[] somemessage = invocation.getSelectedMessages();
        	String[] listData=new String[somemessage.length];
        	for (int i = 0; i < somemessage.length; i++) {
        		IHttpService httpservice = somemessage[i].getHttpService();
        		listData[i]=httpservice.getHost(); 
        		//jButton3.setText(httpservice.getHost());
        	}
    		jList2.setListData(listData);
        	this.invocation = invocation;
        	
        	return Arrays.asList(menuItem);
    	}else {
    		return null;
    	}
        
    }
    


	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		// TODO Auto-generated method stub
		
	}
}
