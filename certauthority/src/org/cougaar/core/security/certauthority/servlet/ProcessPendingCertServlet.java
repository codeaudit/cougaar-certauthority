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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.certauthority.PendingCertCache;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.NodeConfiguration;
import org.cougaar.core.security.services.util.CACertDirectoryService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.util.SecurityServletSupport;

public class ProcessPendingCertServlet extends  HttpServlet
{
  //private CaPolicy caPolicy = null;            // the policy of the CA
  private NodeConfiguration nodeConfiguration;
  private CACertDirectoryService caOperations=null;
  private SecurityServletSupport support;

  public ProcessPendingCertServlet(SecurityServletSupport support) {
    this.support = support;
  }

  public void init(ServletConfig config) throws ServletException
  {
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    PrintWriter out=res.getWriter();
    res.setContentType("text/html");
    String alias=req.getParameter("alias");
    //String role=req.getParameter("role");
    String cadnname=req.getParameter("cadnname");
    out.println("<html>");
    out.println("<script language=\"javascript\">");
    out.println("function submitme(form)");
    out.println("{ form.submit()}</script>");
    out.println("</head>");

    out.println("<body>");

    if((alias==null)||(alias=="")) {
      out.println("Error in getting the certificate alias");
      out.flush();
      out.close();
      return;
    }
    if((cadnname==null)||(cadnname=="")) {
      out.println("Error in getting the CA's DN ");
      out.flush();
      out.close();
      return;
    }

    try {
      //caPolicy = configParser.getCaPolicy(cadnname);
      nodeConfiguration = new NodeConfiguration(cadnname,
						support.getServiceBroker());

      /*
      CertDirectoryServiceRequestor cdsr =
	new CertDirectoryServiceRequestorImpl(caPolicy.ldapURL, caPolicy.ldapType,
					      support.getServiceBroker(), cadnname);
      caOperations = (CertDirectoryServiceCA)
	support.getServiceBroker().getService(cdsr, CertDirectoryServiceCA.class, null);
        */
      caOperations = (CACertDirectoryService)
	support.getServiceBroker().getService(this, CACertDirectoryService.class, null);
    }
    catch (Exception e) {
      out.print("Unable to read policy file: " + e);
      out.flush();
      out.close();
      return;
    }

    String actionType = req.getParameter("actiontype");
    // 0 is deny, 1 is approve, -1 is unknown status
    if (actionType != null) {
      // retrieve pending certificate
      X509Certificate  certimpl;
      try {
        //certimpl=ldapentries[0].getCertificate();
        PendingCertCache pendingCache =
	  PendingCertCache.getPendingCache(cadnname, support.getServiceBroker());
        certimpl = (X509Certificate)
          pendingCache.getCertificate(nodeConfiguration.getPendingDirectoryName(cadnname),
				      alias);

        if (actionType.indexOf("Approve") >= 0) {
          caOperations.publishCertificate(certimpl,
					  CertificateUtility.EntityCert,null);
          out.println("Certificate is now approved: " +
            certimpl.getSubjectDN().getName());
          // need to move to approved directory
          pendingCache.moveCertificate(
            nodeConfiguration.getPendingDirectoryName(cadnname),
	    nodeConfiguration.getX509DirectoryName(cadnname),
	    alias);
        }
        if (actionType.indexOf("Deny") >= 0) {
          out.println("Certificate is denied: " +
            certimpl.getSubjectDN().getName());
          // need to move to denied directory
          pendingCache.moveCertificate(
	    nodeConfiguration.getPendingDirectoryName(cadnname),
	    nodeConfiguration.getDeniedDirectoryName(cadnname), alias);
        }
      }
      catch (Exception exp) {
        out.println("error-----------  "+exp.toString());
        out.flush();
        out.close();
        return;
      }

    }
    String uri = req.getRequestURI();
    String certlistUri = uri.substring(0, uri.lastIndexOf('/')) + "/PendingCertificateServlet";
    out.println(appendForm(certlistUri,cadnname));

    out.println("</body>");
    out.println("</html>");

  }
  private String appendForm(String posturl, String caDNName) {

    StringBuffer sb=new StringBuffer();
     sb.append("<form name=\"certlist\" action=\"" +posturl
	       + "\" method=\"post\">");
     sb.append("<input type=\"hidden\" name=\"cadnname\" value=\""
		+caDNName + "\">");
     //sb.append("<input type=\"hidden\" name=\"role\" value=\""
     //       + role + "\">");
     sb.append("<a Href=\"javascript:submitme(document.certlist)\">"
		+ "Back to List "+"</a></form>");
     return sb.toString();
  }

  protected void doGet(HttpServletRequest req,
		       HttpServletResponse res)
    throws ServletException, IOException
  {
  }

  public String getServletInfo()
  {
    return("Process the order to either deny or approve a pending certificate.");
  }


}

