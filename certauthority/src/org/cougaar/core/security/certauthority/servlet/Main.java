/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 


package org.cougaar.core.security.certauthority.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.security.PrivilegedAction;
import java.security.AccessController;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.util.SecurityServletSupport;

public class Main
  extends HttpServlet
{
  private SecurityServletSupport support;
  private CertificateCacheService  cacheService=null;

  public Main(SecurityServletSupport support) {
    this.support = support;
  }
 
  public void init(ServletConfig config)
    throws ServletException
  {
    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
        cacheService = (CertificateCacheService)
          support.getServiceBroker().getService(this,
					    CertificateCacheService.class,
					    null);
        return null;
      }
    });
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html><head><title>Cougaar Certificate Authority</title></head>");

    out.println("<body><font face=\"arial black\" color=\"#3300cc\">");
    out.println("<h1>Cougaar Certificate Authority</h1></font>");
    out.println("<h2>Select action in left frame</h2>");

    Enumeration aliases = cacheService.getAliasList();
    if (!aliases.hasMoreElements()) {
      // No Ca key has been generated yet
      out.println("<br><br><b>WARNING!</b>");
      out.println("<br>At list one CA key must be generated before the CA can be used.");
      out.println("<br>Select \"Create CA key\" in the left frame.");
    }
    out.println("</body></html>");

    out.flush();
    out.close();
  }
  
  public String getServletInfo()  {
    return("Certificate Authority home");
  }
  
}
