/*
 *  
 * @Author       : Zekun WANG(wangzekun.felix@gmail.com)
 * @CreateTime   : 2022-01-14 22:04:44
 * @LastEditTime : 2022-01-15 00:02:24
 * @LastEditors  : Zekun WANG
 * @FilePath     : \VPN_Project\src\basictools\tools.java
 * @Description  : Some tools for developing and make the code more realizable
 *  
 */
package basictools;

import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class tools {
    public static String Encode2String(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] Decode2Bytes(String str) {
        return Base64.getDecoder().decode(str);
    }

    public static String GetCurrentTime() {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        Date date = new Date();
        return formatter.format(date);
    }

    public static boolean CompareTime(String t1, String t2) {
        String[] s1 = t1.split(":");
        String[] s2 = t2.split(":");
        int l = s1.length-1;
        for (int i=0; i<l; i++) {
            if(!s1[i].equals(s2[i])) {return false;}
        }
        
        if(Math.abs(Integer.parseInt(s1[l])-Integer.parseInt(s2[l]))>1) {return false;}

        return true;
    }

    
}