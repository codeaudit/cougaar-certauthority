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
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.security.PrivilegedAction;
import java.security.AccessController;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.crypto.ldap.LdapEntry;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.services.ldap.MultipleEntryException;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.service.LoggingService;

public class RevokeCertificateServlet
extends HttpServlet
{
  public static String HEADER_WITH_SCRIPT = "<html>" +
  "<script language=\"javascript\">" +
  "function submitme(form)" +
  "{ form.submit()}</script>" +
  "</head>" +
  "<body>";
  private SecurityPropertiesService secprop = null;
  private CertificateManagementService keymanagement=null;
  
  javax.servlet.ServletContext context=null;
  protected boolean debug = false;
  private LoggingService log;

  private SecurityServletSupport support;
  public RevokeCertificateServlet(SecurityServletSupport support) {
    this.support = support;

    this.log = (LoggingService)
      support.getServiceBroker().getService(this,
                                            LoggingService.class, null);

  }

  public void init(ServletConfig config) throws ServletException
    {
      context=config.getServletContext();

      AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
          secprop = (SecurityPropertiesService)
             support.getServiceBroker().getService(this, SecurityPropertiesService.class, null);
          return null;
        }
      });
     
      debug = (Boolean.valueOf(secprop.getProperty(SecurityPropertiesService.CRYPTO_DEBUG,
                                                   "false"))).booleanValue();
      if(debug)
        log.debug(" context is :"+ context.toString());
    }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
    {
      String revokeType = req.getParameter("revoke_type");
    
      if(revokeType != null && revokeType.equals("agent")) {
        if(log.isDebugEnabled()){
          log.debug(" got request to revoke certificate with agent name ");
        }
        revokeAgentCertificate(req, res); 
      }
      else {
        if(log.isDebugEnabled()){
          log.debug(" got request to revoke Certificate with unique identifier ");
        }
        revokeCertificate(req, res);
      }
    }
  
  private void revokeCertificate(HttpServletRequest  req, HttpServletResponse res) 
    throws ServletException,IOException 
    {
      String distinguishedName=null;
      String domain=null;
      final String cadnname=req.getParameter("cadnname");
      boolean error = false;
      PrintWriter out = res.getWriter();
      res.setContentType("text/html");   
      out.println(getHeaderWithScript());
   
      distinguishedName=req.getParameter("distinguishedName");
      domain=req.getParameter("domain");
      
      if((distinguishedName==null)||(distinguishedName=="")) {
        out.println("Error in getting the certificate unique identifier");
        error = true;
      }
      if((cadnname==null)||(cadnname=="")) {
        out.println("Error in getting the CA's DN ");
        error = true;
      }

      if(error) {
        out.println(getFooter());
        out.flush();
        out.close();
        return; 
      }
    
      int status = 0;
      String uri = req.getRequestURI();
      String certlistUri = uri.substring(0, uri.lastIndexOf('/')) + "/CertificateList";
      try {
        AccessController.doPrivileged(new PrivilegedAction() {
          public Object run() {
        keymanagement =
          (CertificateManagementService)support.getServiceBroker().getService(
            new CertificateManagementServiceClientImpl(cadnname),
            CertificateManagementService.class, null);
            return null;
          }
        });
        String uniqueIdentifier=distinguishedName;
        status=keymanagement.revokeCertificate(cadnname,uniqueIdentifier);
      }
      catch (MultipleEntryException multipleexp) {
        out.print("Multiple entry found for : " + multipleexp.getMessage());
        out.println(appendForm(certlistUri,cadnname,domain));
        out.println(getFooter());
        out.flush();
        out.close();
        return;
      }
      catch (Exception generalexp) {
        out.print("Error has occured due to  following reason  : "
                  + generalexp.getMessage());
        out.println(appendForm(certlistUri,cadnname,domain));
        out.println(getFooter()); 
        out.flush();
        out.close();
        return;
      }
    
      out.println(getStatusMsg(status, distinguishedName));
      out.println("<p>");
      out.println(appendForm(certlistUri,cadnname,domain));
      out.println(getFooter()); 
    }
  
  private void revokeAgentCertificate(HttpServletRequest  req, HttpServletResponse res) 
    throws ServletException,IOException 
    {
      //PrintWriter out = res.getWriter();
      PrintStream out = new PrintStream(res.getOutputStream());
      String agentName = req.getParameter("agent_name");
      final String caDN = req.getParameter("ca_dn");
      String replyFormat = req.getParameter("reply_format");
      boolean replyHtml = false;
      if(replyFormat != null && replyFormat.equalsIgnoreCase("html")) {
        replyHtml = true;
      }
      boolean error = false;
      if(replyHtml) {
        out.println(getHeader());
      }
      if(agentName == null || agentName == "") {
        out.println("Error getting name of agent");
        error = true;
      }
      if(caDN == null || caDN == "") {
        out.println("Error getting the certificate distinguished name");
        error = true;
      }
    
      if(error) {
        if(replyHtml) {
          out.println(getFooter());
        }
        out.flush();
        out.close();
        return; 
      }
      out.println("Trying to get CertificateManagementService for caDN " + caDN + "agent name :"+agentName+"<br> " );
      int status = 0;
      try  {
        AccessController.doPrivileged(new PrivilegedAction() {
          public Object run() {
        keymanagement =(CertificateManagementService)support.getServiceBroker().getService(
          new CertificateManagementServiceClientImpl(caDN),
          CertificateManagementService.class, null);
             return null;
          }
        });
        if(keymanagement==null) {
          out.println("CertificateManagementService  is null ");
        }
        status = keymanagement.revokeAgentCertificate(caDN, agentName);
      }
      catch (MultipleEntryException mee) {
        out.println("Multiple entry found for : " + mee.getMessage());
        error = true;
      }
      catch (Exception e) {
        out.println("Error has occured due to  following reason  : "
                    + e.getMessage());
        e.printStackTrace();
        error = true;
      }
	  
      if(!error) {
        out.println(getStatusMsg(status, agentName));	   
        if(replyHtml) {
          out.print("<p>");
        }
      }
      if(replyHtml) {
        out.println(getFooter());
      }
      out.flush();
      out.close();
    }
  
  private String getStatusMsg(int status, String uId) {
    StringBuffer sb = new StringBuffer();
    if(status==1) {
      sb.append("Successfully Revoked certificate : ");
    }
    else if(status==-2) {
      sb.append(" Certificate has already been revoked  : ");
    }
    else if(status==-3) {
      sb.append("Not Enough privileges to Revoke CA  Certificate  : ");
    }
    else {
      sb.append("Error in  Revoking  certificate : ");
    }
    sb.append(uId);
    return sb.toString(); 
  }
  
  private String getHeaderWithScript() {
    return HEADER_WITH_SCRIPT;
  }
  
  private String getHeader() {
    return "<html><body>"; 
  }
  private String getFooter() {
    return "</body></html>"; 
  }
  
  private String appendForm(String posturl, String caDNName, String domain) {
    
    StringBuffer sb=new StringBuffer();
    sb.append("<form name=\"certlist\" action=\"" + posturl
              + "\" method=\"post\">");
    sb.append("<input type=\"hidden\" name=\"cadnname\" value=\""
              + caDNName + "\">");
    sb.append("<input type=\"hidden\" name=\"domain\" value=\""
              + domain + "\">");
    sb.append("<a Href=\"javascript:submitme(document.certlist)\">"
              + "Back to List "+"</a></form>");
    return sb.toString();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
    {
      PrintWriter out=res.getWriter();
      res.setContentType("text/html");
    
      if(context==null)
        {
          out.println(" got context as null");
        }
      /*Enumeration enumn= context.getServletNames();
        for(;enumn.hasMoreElements();)
        {
	String propname=(String)enumn.nextElement();
       	out.println(" Got servlet  name :"+propname );
        }
      */
      Enumeration enum = context.getAttributeNames();
      while(enum.hasMoreElements())
        {
          String propname=(String)enum.nextElement();
          out.println(" Got propert name :"+propname);
          log.debug(" Got propert name :"+propname);
          out.flush();
          if((propname.startsWith("java"))||(propname.startsWith("org.apache"))) {
            continue;
          }
          String value=(String )context.getAttribute(propname);
          log.debug(" property value :"+ value);
          out.println(" property value :"+ value);
        }
    }

  public String getServletInfo()
    {
      return("Displaying details of certificate with give hash map");
    }

  public String createtable(LdapEntry[] ldapentries)
    {
      StringBuffer sb=new StringBuffer();
      sb.append("<table align=\"center\">\n");
      sb.append("<TR><TH> DN-Certificate </TH><TH> Status </TH><TH> DN-Signed By </TH></TR>\n");
      for(int i = 0 ; i < ldapentries.length ; i++) {
        sb.append("<TR><TD><a Href=\"../CertificateDetails?distinguishedName="
                  + ldapentries[0].getUniqueIdentifier() + "\">" 
                  + ldapentries[0].getCertificate().getSubjectDN().getName()
                  + "</a><TD>\n");
        //sb.append("<TD>" + ldapentries[0].getStatus()+"</TD>\n" );
        sb.append("<TD>" + ldapentries[0].getCertificate().getIssuerDN().getName()
                  +"</TD></TR>\n");

      }
      sb.append("</table>");
      return sb.toString();
    }

  private class CertificateManagementServiceClientImpl
  implements CertificateManagementServiceClient
  {
    private String caDN;
    public CertificateManagementServiceClientImpl(String aCaDN) {
      caDN = aCaDN;
    }
    public String getCaDN() {
      return caDN;
    }
  }
}
