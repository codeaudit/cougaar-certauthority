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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.util.SecurityServletSupport;

public class Browser
  extends HttpServlet
{
  private SecurityServletSupport support;
  public Browser(SecurityServletSupport support) {
    this.support = support;
  }
 
  public void init(ServletConfig config) throws ServletException {
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    String uri = req.getRequestURI();
    String path = uri.substring(0, uri.lastIndexOf('/'));

    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html><head><title>Cougaar Certificate Authority</title></head>");
    out.println("<body>");
    // Certificate Signing requests
    out.println("<p><a href=\"" + path + "/CertificateSigningRequest\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>Request Certificate</b></big></a>");
    // Browser Certificate Signing requests
    out.println("<p><a href=\"" + path + "/BrowserSigningRequest\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>Request Browser Certificate</b></big></a>");
    // Certificate List
    out.println("<p><a href=\"" + path + "/CertificateList\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>Certificate List</b></big></a>");

    // Pending Certificate List
    out.println("<p><a href=\"" + path + "/PendingCertificateServlet\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>Pending Certificate List</b></big></a>");

    out.println("<p><big><font color=\"black\"><b>CA keys management</b></big></p>");
    out.println("<BLOCKQUOTE style=\"MARGIN-RIGHT: 0px\">");
    out.println("<p><a href=\"" + path + "/CreateCaKeyServlet\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>Create CA key</b></big></a></p>");
    out.println("<p><a href=\"" + path + "/ListCaKeysServlet\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>List CA keys</b></big></a></p>");
    out.println("</BLOCKQUOTE><p></body></html>");
    out.flush();
    out.close();
  }
  
  public String getServletInfo()  {
    return("Certificate Authority home");
  }
  
}
