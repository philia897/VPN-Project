/*
 *  
 * @Author       : Zekun WANG(wangzekun.felix@gmail.com)
 * @CreateTime   : 2021-11-19 21:33:47
 * @LastEditTime : 2021-12-22 23:17:33
 * @LastEditors  : Do not edit
 * @FilePath     : \VPN_Project\src\test\TestRunner.java
 * @Description  : To start the JUnit test.
 *  
 */
package test;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

public class TestRunner {
   public static void main(String[] args) {
      Result result = JUnitCore.runClasses(SessionEncryptionTest.class);
      for (Failure failure : result.getFailures()) {
         System.out.println(failure.toString());
      }
      System.out.println(result.wasSuccessful());
   }
} 
