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
import java.io.ObjectOutputStream;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.io.PrintWriter;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.util.Duration;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.service.LoggingService;

import sun.security.x509.X500Name;

public class CAInfoServlet
  extends HttpServlet {

  private ConfigParserService configParser = null;
  private LoggingService log;
  private SecurityServletSupport support;

  private CAInfo _info = null;
  private String httpsport = null;

  public CAInfoServlet(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
			       LoggingService.class, null);
	String autoconfig = System.getProperty("org.cougaar.core.autoconfig", "false");
	if (!autoconfig.equals("true")) {
	   throw new RuntimeException("This servlet should not be loaded except for unzip & run.");
	}
  }

  public void init(ServletConfig config) throws ServletException
  {
    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
    configParser = (ConfigParserService)
           support.getServiceBroker().getService(this, ConfigParserService.class, null);
        return null;
      }
    });
    httpsport = System.getProperty("org.cougaar.lib.web.https.port", null);
  }

  private CAInfo getCAInfo() {
    if (log.isDebugEnabled()) {
      log.debug("getCAInfo.");
    }

    X500Name [] caDNs = configParser.getCaDNs();
    if (caDNs == null || caDNs.length == 0)
      return null;
    X500Name caDN = caDNs[0];
    KeyRingService krs = (KeyRingService)
      AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
          return support.getServiceBroker().getService(this, KeyRingService.class, null);
        }
      });
    List l = krs.findCert(caDN, KeyRingService.LOOKUP_KEYSTORE, true);
    if (l == null || l.size() == 0) {
      if (log.isDebugEnabled()) {
        log.debug("Cannot find CA certificate " + caDN + " but CA key is being generated.");
      }
      return null;
    }
    CertificateStatus cs = (CertificateStatus)l.get(0);
    X509Certificate [] certChain = null;
    try {
      certChain = krs.checkCertificateTrust((X509Certificate)cs.getCertificate());
    } catch (CertificateException cex) {
      if (log.isWarnEnabled()) {
        log.warn("CA certificate not trusted!", cex);
        return null;
      }
    }

    // cert request will use https, so need to wait til server cert has
    // been approved
    if (!(httpsport == null || httpsport.equals("-1"))) {
/*
      l = krs.findCert(NodeInfo.getHostName(), KeyRingService.LOOKUP_KEYSTORE, true);
      if (l == null || l.size() == 0) {
*/
      if (!krs.isManagerReady()) {
        if (log.isWarnEnabled()) {
          log.warn("Host cert has not been signed by CA yet.");
        }
        return null;
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("replying with CA info.");
    }

    SecurityPolicy[] sp =
      configParser.getSecurityPolicies(CryptoClientPolicy.class);
    CryptoClientPolicy ccp = (CryptoClientPolicy) sp[0];
    
    TrustedCaPolicy tc = new TrustedCaPolicy();
    tc.caDN = caDN.toString();

    CaPolicy caPolicy = configParser.getCaPolicy(tc.caDN);
    tc.caURL = "";
    tc.certDirectoryUrl = caPolicy.ldapURL;
    tc.certDirectoryPrincipal = caPolicy.ldapPrincipal;
    tc.certDirectoryCredential = caPolicy.ldapCredential;
    tc.certDirectoryType = caPolicy.ldapType;
    tc.setCertificateAttributesPolicy(ccp.getCertificateAttributesPolicy());

    CAInfo info = new CAInfo();
    info.caCert = certChain;
    info.caPolicy = tc;

    return info;
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    // if no parameter, returns the whole TrustedCaPolicy,
    // otherwise it is actually a set function
    // for test script usage
    String howLong = req.getParameter("howLong");
    // need to set time envelope to 0

    ServletOutputStream out = res.getOutputStream();
    if (howLong != null) {
      String response = "";
      String caDn = req.getParameter("cadn");
      if (caDn == null) {
	X500Name [] caDns = configParser.getCaDNs();   
	if (caDns.length != 0) {
	  caDn = caDns[0].getName();	
	}
      }
      CaPolicy caPolicy = configParser.getCaPolicy(caDn);
      if (caPolicy != null) {
	String timeEnvelope = req.getParameter("timeEnvelope");
	try {
	  Duration duration = new Duration(support.getServiceBroker());
	  duration.parse(howLong);
	  caPolicy.howLong = duration.getDuration();
	  if (log.isDebugEnabled()) {
	    log.debug("Duration is set to " + caPolicy.howLong);
	  }
	  caPolicy.validity = howLong;
	  if (timeEnvelope == null) {
	    timeEnvelope = "1 s";
	  }
	  caPolicy.timeEnvelopeString = timeEnvelope;
	  duration.parse(timeEnvelope);
	  caPolicy.timeEnvelope = duration.getDuration();
   				
	  response = "Changed validity to " + caPolicy.validity + ", timeEnvelope to " + caPolicy.timeEnvelopeString
	    + " for " + caDn;
	} catch (Exception ex) {
	  response = "Exception in processing " + howLong + " or " + timeEnvelope;
	}
      }
      else {
	response = "No such caDn " + caDn;
      }
      out.print(response);
      out.flush();
      out.close();
    }
    else { // if (howLong != null)
      try {
	synchronized (this) {
	  if (_info == null) {
	    _info = getCAInfo();
	    if (_info == null) {
	      out.flush();
	      out.close();
	      return;
	    }
	  }
	}

	res.setContentType("text/html");
	ObjectOutputStream oos = new ObjectOutputStream(out);
	oos.writeObject(_info);
	oos.flush();
	oos.close();
      }
      catch (Exception e) {
	if (log.isWarnEnabled()) {
	  log.warn("Unable to response ", e);
	}
	out.flush();
	out.close();
      }
    }
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
  {
  	PrintWriter out = res.getWriter();
	out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
	 out.println("<html>");
	 out.println("<head>");
	 out.println("<title>CA info request </title>");
	 out.println("</head>");
	 out.println("<body>");
	 out.println("<H2> CA info request</H2>");
	 out.println("<table>");
	 out.println("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");
  	out.println("This servlet handles post, and will only be loaded for unzip & run:<br>\n");
  	out.println("1. If no parameter is supplied, TrustedCaPolicy and CA certificate chain are returned.<br>\n");
  	out.println("2. If cadn and howLong parameters are supplied, CA policy will be set to the new validity value,<br>\n");
  	out.println("  optionally timeEnvelope can be supplied to specify value for timeEnvelop field of CA policy.<br>\n");
  	X500Name [] caDNs = configParser.getCaDNs();
//  	out.println("DN for CA: <input name=\"cadn\" type=\"text\" value=\"\"><br>");
	out.println("Select CA: <select id=\"cadn\" name=\"cadn\">");
	 for (int i = 0 ; i < caDNs.length ; i++) {
	   out.println("<option value=\"" + caDNs[i].toString() + "\">" 
		   + caDNs[i].toString() + "</option>");
	 }
	 out.println("</select><br>");
	out.println("<br>how Long .e.g. 1a d, 2a m, 3a s: <input name=\"howLong\" type=\"text\" value=\"1 s\"><br>");
	out.println("timeEnvelope, same format as how long: <input name=\"timeEnvelope\" type=\"text\" value=\"1 s\"><br>");
	out.println("<br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");
	out.println("<input type=\"reset\">");
	out.println("</form>");
	out.println("</body></html>");
  	out.flush();
  	out.close();
  	return;
  }

  public String getServletInfo()
  {
    return("For unzip & run only, returns CA certificate attribute policy and CA certificate.");
  }

}
