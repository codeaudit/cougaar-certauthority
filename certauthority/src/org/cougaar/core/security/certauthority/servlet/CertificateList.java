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
import java.net.URLEncoder;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.naming.CertificateEntry;
import org.cougaar.core.security.services.util.CACertDirectoryService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.service.LoggingService;

import sun.security.x509.X500Name;

public class CertificateList
  extends HttpServlet
{
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;

  private X500Name[] caDNs = null;
  //private CaPolicy caPolicy = null;            // the policy of the CA
  //private CertDirectoryServiceClient certificateFinder=null;
  private CACertDirectoryService search;
  private LoggingService log;

  private SecurityServletSupport support;
  public static final int STATUS_ORDERING = 1;
  public static final int DN_ORDERING = 2;
  public static final int FROM_ORDERING = 3;
  public static final int TO_ORDERING = 4;

  public CertificateList(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
			       LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
    try {
      AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
          secprop = (SecurityPropertiesService)
             support.getServiceBroker().getService(this, SecurityPropertiesService.class, null);
      configParser = (ConfigParserService)
            support.getServiceBroker().getService(this, ConfigParserService.class, null);
      search = (CACertDirectoryService)
        support.getServiceBroker().getService(this, CACertDirectoryService.class, null);
          return null;
        }
      });
      search.refreshBlackboard();
    }
    catch (Exception e) {
      log.error("Unable to initialize servlet:" + e);
    }
  }

  /** Return requested ordering from request
   */
  private int getOrdering(HttpServletRequest req) {
    int ordering = 0;
    try {
      ordering = Integer.parseInt(req.getParameter("ordering"));
    }
    catch (Exception e) {
      // Nothing to do. Use the default ordering value
    }
    return ordering;
  }
  private String getCaDn(HttpServletRequest req) {
    return req.getParameter("cadnname");
  }

  public void doPost (HttpServletRequest req, HttpServletResponse res)
    throws ServletException,IOException
  {
    PrintWriter out=res.getWriter();
    String cadnname = getCaDn(req);
    if (log.isDebugEnabled()) {
      log.debug("doPost:" + cadnname);
    }
    if((cadnname==null)||( cadnname=="")) {
      out.print("Error ---Unknown  type CA dn name :");
      out.flush();
      out.close();
      return;
    }
    doCertificateList(cadnname, out, req, getOrdering(req));
    out.println("</body></html>");
    out.flush();
    out.close();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
  {
    res.setContentType("text/html");
    PrintWriter out=res.getWriter();

    String cadnname = getCaDn(req);
    if (log.isDebugEnabled()) {
      log.debug("doGet: " + cadnname);
    }
    if ((cadnname==null)||( cadnname=="")) {
      doCaList(out, req);
    }
    else {
      doCertificateList(cadnname, out, req, getOrdering(req));
    }
    out.println("</body></html>");
    out.flush();
    out.close();
  }

  public String getServletInfo()
  {
    return("List all certificate specified by CAS dn name");
  }

  /**
   * Display the list of certificates
   */
  private void doCertificateList(String cadnname, PrintWriter out,
				 HttpServletRequest req, int ordering) {
    /*
    try {
      caPolicy = configParser.getCaPolicy(cadnname);

      CertDirectoryServiceRequestor cdsr =
	new CertDirectoryServiceRequestorImpl(caPolicy.ldapURL, caPolicy.ldapType,
					      support.getServiceBroker(), cadnname);
      certificateFinder = (CertDirectoryServiceClient)
	support.getServiceBroker().getService(cdsr, CertDirectoryServiceClient.class, null);
    }
    catch (Exception e) {
      out.print("Unable to read policy file: " + e);
      out.flush();
      out.close();
      return;
    }
    CertDirServiceRequestor cdsr =
      new CertDirServiceRequestor(support.getServiceBroker(), cadnname);
    */

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate List</title>");
    out.println("<script language=\"javascript\">");
    out.println("function submitme(form)");
    out.println("{ form.submit()}</script>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Certificate List</H2>");
    out.println("<H3>Issuer: " + cadnname + "</H3>");
    //out.println("<H3>LDAP:   " + caPolicy.ldapURL + "</H3>");

    /*
    String filter = "(cn=*)";
    LdapEntry[] ldapentries = certificateFinder.searchWithFilter(filter);
    out.println("<H3>" + ldapentries.length + " entries</H3>");
    */
    List l = search.getAllCertificates();
    out.println("<H3>" + l.size() + " entries</H3>");

    out.println("<table>");

    String uri = req.getRequestURI();
    String certDetailsUri = uri.substring(0, uri.lastIndexOf('/'))
      + "/CertificateDetailsServlet";

    /*
    if((domain==null)||(domain=="")) {
      domain = null;
    }
    if (log.isDebugEnabled()) {
      log.debug("calling create table will domain:" + domain);
    }
    */
    out.println(createtable(l, cadnname,
			    certDetailsUri, ordering));
  }

  /**
   * Display a drop-down list to display the list of CAs
   */
  private void doCaList(PrintWriter out, HttpServletRequest req) {
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate List</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Certificate List</H2>");

    caDNs = configParser.getCaDNs();
    if (log.isDebugEnabled()) {
      if (caDNs == null || caDNs.length == 0) {
        log.debug("No CA DN");
      }
      else {
        for (int i = 0 ; i < caDNs.length ; i++) {
          log.debug("CA DN: " + caDNs[i].toString());
        }
      }
    }

    if (caDNs == null) {
      out.println("No CA has been configured yet");
    }
    else {
      String uri=req.getRequestURI();
      out.println("<table>");
      out.println("<form action=\"" + uri + "\" method =\"post\">");
      out.println("<tr ><td colspan=\"3\">");
      // Domain
      //out.println("Name space: <select id=\"domain\" name=\"domain\">");
      /*
      if (domains != null) {
	for (int i = 0 ; i < domains.length ; i++) {
	  out.println("<option value=\"" + domains[i] + "\">"
		      + domains[i] + "</option>");
	}
      }
      else {
      }
      */
      out.println("</select>");

      //out.println("Domain <input name=\"domain\" type=\"text\" value=\"\">");

      // Table separators
      out.println(" <br> <br></td></tr>");
      out.println("<tr ><td colspan=\"3\">");

      // CA
      out.println("Select CA: <select id=\"cadnname\" name=\"cadnname\">");

      for (int i = 0 ; i < caDNs.length ; i++) {
	out.println("<option value=\"" + caDNs[i].toString() + "\">"
		    + caDNs[i].toString() + "</option>");
      }
      out.println("</select>");
      //out.println("DN for CA <input name=\"cadnname\" type=\"text\" value=\"\">");

      out.println(" <br> <br></td></tr>");
      out.println("</tr><tr><td></td><td><br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");
      out.println("<input type=\"reset\"></td><td></td></tr>");
      out.println("</form></table>");
    }
  }

  public String createtable(List l, String cadnname,
			    String certDetailUri,
			    int ordering)
  {
    StringBuffer sb=new StringBuffer();
    sb.append("<table align=\"center\" border=\"2\">\n");
    String encodedCaName = "";
    try {
      encodedCaName = URLEncoder.encode(cadnname, "UTF-8");
    }
    catch (Exception e) {
      // Nothing to do
    }
    sb.append("<TR><TH>" +
	      "<a Href=\"?cadnname="
	      + encodedCaName + "&ordering="
	      + DN_ORDERING + "\">DN-Certificate</a>" +
	      "</TH><TH>" +
	      "<a Href=\"?cadnname="
	      + encodedCaName + "&ordering="
	      + STATUS_ORDERING + "\">Status</a>" + 
	      "</TH><TH>" +
	      "<a Href=\"?cadnname="
	      + encodedCaName + "&ordering="
	      + FROM_ORDERING + "\">From</a>" + 
	      "</TH><TH>" +
	      "<a Href=\"?cadnname="
	      + encodedCaName + "&ordering="
	      + TO_ORDERING + "\">To</a>" + 
	      "</TH><TH>DN-Signed By</TH></TR>\n");

    switch (ordering) {
    case STATUS_ORDERING:
      Collections.sort(l, new StatusComparator());
      break;
    case FROM_ORDERING:
      Collections.sort(l, new FromComparator());
      break;
    case TO_ORDERING:
      Collections.sort(l, new ToComparator());
      break;
    case DN_ORDERING:
    default:
      Collections.sort(l, new DnComparator());
      break;
    }
    //for(int i = 0 ; i < ldapentries.length ; i++) {
    for(int i = 0 ; i < l.size() ; i++) {
      CertificateEntry entry = (CertificateEntry)l.get(i);
      X509Certificate cert = entry.getCertificate();
      sb.append("<TR><TD>\n");
      sb.append("<form name=\"form" + i
		+ "\" action=\"" + certDetailUri + "\" method=\"post\">");
      sb.append("<input type=\"hidden\" name=\"distinguishedName\" value=\""
		//+ ldapentries[i].getUniqueIdentifier()+"\">");
                + CertificateUtility.getUniqueIdentifier(cert)+"\">");
      sb.append("<input type=\"hidden\" name=\"cadnname\" value=\""
		+ cadnname + "\">");
      //sb.append("<input type=\"hidden\" name=\"domain\" value=\"" + domain + "\">");
      sb.append("<a Href=\"javascript:submitme(document.form"
		+ i +")\">"
		+ cert.getSubjectDN().getName()
		+"</a></form></TD>\n");
      sb.append("<TD>"+entry.getCertificateRevocationStatus()+"</TD>\n" );
      sb.append("<TD>"+cert.getNotBefore().toString()+"</TD>\n" );
      sb.append("<TD>"+cert.getNotAfter().toString()+"</TD>\n" );
      sb.append("<TD>"+cert.getIssuerDN().getName()
		+"</TD></TR>\n");
    }
    sb.append("</table>");
    return sb.toString();
  }

  private class DnComparator
    implements Comparator
  {
    public int compare (Object o1, Object o2) {
      CertificateEntry entry1 = (CertificateEntry)o1;
      CertificateEntry entry2 = (CertificateEntry)o2;
      X509Certificate cert1 = entry1.getCertificate();
      X509Certificate cert2 = entry2.getCertificate();
      String name1 = cert1.getSubjectDN().getName()
	+ cert1.getSerialNumber();
      String name2 = cert2.getSubjectDN().getName()
	+ cert2.getSerialNumber();
      return (name1.compareTo(name2));
    }
    public boolean equals(Object obj) {
      return obj.equals(this);
    }
  }

  private class StatusComparator
    implements Comparator
  {
    public int compare (Object o1, Object o2) {
      CertificateEntry entry1 = (CertificateEntry)o1;
      CertificateEntry entry2 = (CertificateEntry)o2;
      X509Certificate cert1 = entry1.getCertificate();
      X509Certificate cert2 = entry2.getCertificate();
      String name1 = entry1.getCertificateRevocationStatus() +
	cert1.getSubjectDN().getName()
	+ cert1.getSerialNumber();
      String name2 = entry2.getCertificateRevocationStatus() +
	cert2.getSubjectDN().getName()
	+ cert2.getSerialNumber();
      return (name1.compareTo(name2));
    }
    public boolean equals(Object obj) {
      return obj.equals(this);
    }
  }
  private class FromComparator
    implements Comparator
  {
    public int compare (Object o1, Object o2) {
      CertificateEntry entry1 = (CertificateEntry)o1;
      CertificateEntry entry2 = (CertificateEntry)o2;
      X509Certificate cert1 = entry1.getCertificate();
      X509Certificate cert2 = entry2.getCertificate();
      if (cert1.getNotBefore() != cert2.getNotBefore()) {
	return cert1.getNotBefore().compareTo(cert2.getNotBefore());
      }
      else {
	String name1 = cert1.getSubjectDN().getName()
	  + cert1.getSerialNumber();
	String name2 = entry2.getCertificateRevocationStatus() +
	  cert2.getSubjectDN().getName()
	  + cert2.getSerialNumber();
	return (name1.compareTo(name2));
      }
    }
    public boolean equals(Object obj) {
      return obj.equals(this);
    }
  }
  private class ToComparator
    implements Comparator
  {
    public int compare (Object o1, Object o2) {
      CertificateEntry entry1 = (CertificateEntry)o1;
      CertificateEntry entry2 = (CertificateEntry)o2;
      X509Certificate cert1 = entry1.getCertificate();
      X509Certificate cert2 = entry2.getCertificate();
      if (cert1.getNotAfter() != cert2.getNotAfter()) {
	return cert1.getNotAfter().compareTo(cert2.getNotAfter());
      }
      else {
	String name1 = cert1.getSubjectDN().getName()
	  + cert1.getSerialNumber();
	String name2 = entry2.getCertificateRevocationStatus() +
	  cert2.getSubjectDN().getName()
	  + cert2.getSerialNumber();
	return (name1.compareTo(name2));
      }
    }
    public boolean equals(Object obj) {
      return obj.equals(this);
    }
  }
}
