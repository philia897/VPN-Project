/*
 *  
 * @Author       : Zekun WANG(wangzekun.felix@gmail.com)
 * @CreateTime   : 2021-12-18 16:56:36
 * @LastEditTime : 2021-12-22 23:16:20
 * @LastEditors  : Do not edit
 * @FilePath     : \VPN_Project\src\test\ClientSimulate.java
 * @Description  : Simulate the client to test the vpn system's functionality.
 *  
 */
package test;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class ClientSimulate {

    public static void main(String[] args) throws IOException {
        Socket socket = new Socket("127.0.0.1", 12345);
        OutputStream os = socket.getOutputStream();
        os.write("你好，服务器。".getBytes());
        InputStream is = socket.getInputStream();
        byte[] bytes = new byte[1024];
        int len = is.read(bytes);
        System.out.println(new String(bytes, 0, len));
        len = is.read(bytes);
        System.out.println(new String(bytes, 0, len));
        os.write("不需要，只是打个招呼~".getBytes());
        os.write("下线了，再见！".getBytes());
        len = is.read(bytes);
        System.out.println(new String(bytes, 0, len));
        socket.close();
        
    }
}
