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
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.service.LoggingService;

public class ListCaKeysServlet
extends  HttpServlet
{
  private KeyRingService keyRingService= null;
  private CertificateCacheService cacheService=null;
  private LoggingService log;

  private SecurityServletSupport support;

  public ListCaKeysServlet(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
					    LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
    {
      AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
      keyRingService = (KeyRingService)
            support.getServiceBroker().getService(this, KeyRingService.class, null);
      cacheService=(CertificateCacheService)
            support.getServiceBroker(). getService(this, CertificateCacheService.class, null);
          return null;
    }
      });
    }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
    {
    }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    res.setContentType("text/html");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>CA Keys List</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>CA Keys List</H2>");
    out.println("<table>");
    out.println("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");


    Enumeration aliases = null;
    if(cacheService!=null) {
      aliases= cacheService.getAliasList();
    }
    else {
      out.println("Unable to get  Certificate Cache Service ");
      out.flush();
      out.close();
      return ;

    }
    out.println("<table align=\"center\" border=\"2\">\n");
    out.println("<TR><TH> DN-Certificate </TH><TH> DN-Signed By </TH></TR>\n");

    while (aliases.hasMoreElements()) {
      String a = (String)aliases.nextElement();
      String cn = cacheService.getCommonName(a);
      List certList = keyRingService.findCert(cn, KeyRingService.LOOKUP_KEYSTORE);
      Iterator it = certList.iterator();
      while (it.hasNext()) {
        CertificateStatus cs = (CertificateStatus)it.next();
	X509Certificate c = cs.getCertificate();

        // not every cert on CA is a CA cert
        if (cs.getCertificateType() != CertificateType.CERT_TYPE_CA)
          continue;

	log.debug("alias=" + a + " - cn=" + cn);
	if (c != null) {
	  out.println("<TR>");
	  out.println("<TD>" + c.getSubjectDN().getName() +"</TD>\n" );
	  out.println("<TD>" + c.getIssuerDN().getName());
	  out.println("</TD></TR>\n");
	}
      }
    }
    out.println("</table>");
    out.flush();
    out.close();

  }

  public String getServletInfo()  {
    return("Generate a CA key");
  }

}
