/*
 *  
 * @Author       : Zekun WANG(wangzekun.felix@gmail.com)
 * @CreateTime   : 2021-12-18 16:55:52
 * @LastEditTime : 2021-12-22 23:17:05
 * @LastEditors  : Do not edit
 * @FilePath     : \VPN_Project\src\test\ServerSimulate.java
 * @Description  : Simulate the server to test the vpn system's functionality.
 *  
 */
package test;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerSimulate {
    public static void main(String[] args) throws IOException, InterruptedException {
        ServerSocket server = new ServerSocket(2277);
        Socket socket = server.accept();
        InputStream is = socket.getInputStream();
        byte[] bytes = new byte[1024];
        int len = is.read(bytes);
        System.out.println(new String(bytes, 0, len));
        OutputStream os = socket.getOutputStream();
        os.write("收到，谢谢！".getBytes());
        os.write("请问你要什么？".getBytes());
        len = is.read(bytes);
        System.out.println(new String(bytes, 0, len));
        len = is.read(bytes);
        System.out.println(new String(bytes, 0, len));
        os.write("收到，再见！".getBytes());
        Thread.sleep(10000);
        socket.close();
        server.close();
    }
}
