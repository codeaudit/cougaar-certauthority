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
import java.security.cert.X509Certificate;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.crypto.Base64;
import org.cougaar.core.security.crypto.CertDirServiceRequestor;
import org.cougaar.core.security.crypto.CertificateCacheConstants;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.naming.CertificateEntry;
import org.cougaar.core.security.services.util.CACertDirectoryService;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.service.LoggingService;

public class DownloadCertificateServlet extends  HttpServlet
{
  //private ConfigParserService configParser = null;
  private LoggingService log;

  //private CertDirectoryServiceClient certificateFinder=null;
  private CACertDirectoryService search;
  //private CaPolicy caPolicy = null;            // the policy of the CA

  private SecurityServletSupport support;
  public DownloadCertificateServlet(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
			       LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
  }

  public void service (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {

    String distinguishedName=null;
    //String role=null;
    String cadnname=null;

    res.setContentType("text/html");
    if (log.isDebugEnabled()) {
      //log.debug("getContextPath:" + req.getContextPath());
      log.debug("getPathInfo:" + req.getPathInfo());
      log.debug("getPathTranslated:" + req.getPathTranslated());
      log.debug("getRequestURI:" + req.getRequestURI());
      log.debug("getServletPath:" + req.getServletPath());
    }

    distinguishedName=req.getParameter("distinguishedName");
    cadnname=req.getParameter("cadnname");
    if (log.isDebugEnabled()) {
      log.debug("CertificateDetailsServlet. Search DN="
			 + distinguishedName
			 + " - cadnname: " + cadnname);
    }
    if((cadnname==null)||(cadnname=="")) {
      res.getWriter().print("Error in dn name ");
      return;
    }
    /*
    try {
      configParser = (ConfigParserService)
	support.getServiceBroker().getService(this,
					      ConfigParserService.class,
					      null);
      caPolicy = configParser.getCaPolicy(cadnname);

      CertDirectoryServiceRequestor cdsr =
	new CertDirectoryServiceRequestorImpl(caPolicy.ldapURL, caPolicy.ldapType,
					      support.getServiceBroker(), cadnname);
      certificateFinder = (CertDirectoryServiceClient)
	support.getServiceBroker().getService(cdsr, CertDirectoryServiceClient.class, null);

    } catch (Exception e) {
      res.getWriter().print("Unable to read policy file: " + e);
      return;
    }
    */
    CertDirServiceRequestor cdsr =
      new CertDirServiceRequestor(support.getServiceBroker(), cadnname);
    search = (CACertDirectoryService)
      support.getServiceBroker().getService(cdsr, CACertDirectoryService.class, null);

    if((distinguishedName==null)||(distinguishedName=="")) {
      res.getWriter().print("Error in distinguishedName ");
      return;
    }

    /*
    String filter = "(uniqueIdentifier=" +distinguishedName + ")";
    LdapEntry[] ldapentries = certificateFinder.searchWithFilter(filter);
    if(ldapentries==null || ldapentries.length == 0) {
    */
    CertificateEntry ce = search.findCertByIdentifier(distinguishedName);
    if (ce == null) {
      res.getWriter().println("Error: no such certificate found");
      return;
    }

    X509Certificate  certimpl = ce.getCertificate();
    byte[] encoded;
    char[] b64;
    try {
      encoded = certimpl.getEncoded();
      b64 = Base64.encode(encoded);
    } catch (Exception exp) {
      res.getWriter().println("error-----------  "+exp.toString());
      return;
    }

    res.reset();
    if (isCA(certimpl.getSubjectDN().getName())) {
      res.setContentType("application/x-x509-ca-cert");
      res.setHeader("Content-Disposition","inline; filename=\"ca.cer\"");
    } else {
      res.setContentType("application/x-x509-user-cert");
      res.setHeader("Content-Disposition","inline; filename=\"user.cer\"");
    } // end of else

    StringBuffer buf = new StringBuffer();
    buf.append("-----BEGIN CERTIFICATE-----\n");
    buf.append(b64);
    buf.append("\n-----END CERTIFICATE-----\n");
    res.setContentLength(buf.length());
    res.getWriter().print(buf.toString());
    res.getWriter().close();
  }

  public static boolean isCA(String dn) {
    return CertificateUtility.findAttribute(dn, "t").equals(CertificateCacheConstants.CERT_TITLE_CA);
  /*
    StringTokenizer tok = new StringTokenizer(dn,",=",true);
    boolean first = true;
    try {
      while (tok.hasMoreTokens()) {
        if (first) {
          first = false; // first doesn't have a ',' in front
        } else {
          if (!(",".equals(tok.nextToken()))) {
            // bad dn -- expecting ','
            return false;
          } // end of if (!(",".equals(tok.nextToken())))
        } // !first
        String name = tok.nextToken().trim();
        if (!("=".equals(tok.nextToken()))) {
          // bad dn -- expecting '='
          return false;
        } // end of if (!("=".equals(tok.nextToken())))
        String value = tok.nextToken();
        if (name.equalsIgnoreCase("t")) {
          return (value.equalsIgnoreCase("ca"));
        } // end of if (name.equalsIgnoreCase("t"))
      } // end of while (tok.hasMoreTokens())
    } catch (NoSuchElementException e) {
      // invalid dn
    } // end of try-catch
    return false;
    */
  }

  public static boolean isUser(String dn) {
    return CertificateUtility.findAttribute(dn, "t").equals(CertificateCacheConstants.CERT_TITLE_USER);
  /*
    StringTokenizer tok = new StringTokenizer(dn,",=",true);
    boolean first = true;
    String sep;
    try {
      while (tok.hasMoreTokens()) {
        if (first) {
          first = false; // first doesn't have a ',' in front
        } else {
          sep = tok.nextToken();
          if (!(",".equals(sep))) {
            // bad dn -- expecting ','
            return false;
          } // end of if (!(",".equals(tok.nextToken())))
        } // !first
        String name = tok.nextToken().trim();
        sep = tok.nextToken();
        if (!("=".equals(sep))) {
          //bad dn -- expecting '='
          return false;
        } // end of if (!("=".equals(tok.nextToken())))
        String value = tok.nextToken();
        if (name.equalsIgnoreCase("t")) {
          return (value.equalsIgnoreCase("user"));
        } // end of if (name.equalsIgnoreCase("t"))
      } // end of while (tok.hasMoreTokens())
    } catch (NoSuchElementException e) {
      // invalid dn
    } // end of try-catch
    return false;
    */
  }

  public String getServletInfo()  {
    return("Downloads the certificate to the browser");
  }

}
