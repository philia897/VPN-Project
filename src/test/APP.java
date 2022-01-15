/*
 *  
 * @Author       : Zekun WANG(wangzekun.felix@gmail.com)
 * @CreateTime   : 2022-01-14 22:20:11
 * @LastEditTime : 2022-01-14 23:20:55
 * @LastEditors  : Zekun WANG
 * @FilePath     : \VPN_Project\src\test\APP.java
 * @Description  :  Test for practicing
 *  
 */


package test;

import java.sql.Time;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import basictools.tools;

public class APP {
    public static void main(String[] args) throws InterruptedException {
        String s = tools.GetCurrentTime();
        TimeUnit.SECONDS.sleep(2);
        String s2 = tools.GetCurrentTime();
        System.out.println(s + "  |   " + s2);
        System.out.println(tools.CompareTime(s,s2));
    }
}

