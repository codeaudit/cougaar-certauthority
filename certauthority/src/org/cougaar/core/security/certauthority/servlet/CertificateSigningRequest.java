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


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignedObject;
import java.security.cert.X509Certificate;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.security.cm.CMMessage;
import org.cougaar.core.security.cm.message.VerifyAgentAddRequest;
import org.cougaar.core.security.cm.message.VerifyResponse;
import org.cougaar.core.security.cm.service.CMService;
//import org.cougaar.core.security.cm.service.CMServiceProvider;
import org.cougaar.core.security.crypto.CertificateCacheConstants;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.KeyManagementConstants;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import sun.misc.BASE64Decoder;
import sun.security.pkcs.PKCS10;
import sun.security.x509.X500Name;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision: 1.1 $
 */
public class CertificateSigningRequest extends HttpServlet implements BlackboardClient {
  private CertificateManagementService signer;
  private SecurityServletSupport support;
  private ConfigParserService configParser = null;
  private LoggingService log;
  private X500Name[] caDNs = null;
  /**local cache of node certificates to verify the signed digest of Agent Signing Requests*/
  private Map nodeCertMap = new HashMap();
  /**Blackboard service used for Configuration Manager Stuff*/
  private BlackboardService blackboardService = null;
  /**Whether to use the Configuration Manager or not (From "requirepending" element in the cryptoPolicy)*/
  private boolean requirePending = false;
  
  private CMService cmService;
  /**
   * Creates a new CertificateSigningRequest object.
   *
   * @param support DOCUMENT ME!
   *
   * @throws IllegalArgumentException DOCUMENT ME!
   */
  public CertificateSigningRequest(SecurityServletSupport support) {
    if (support == null) {
      throw new IllegalArgumentException("Support services null");
    }

    this.support = support;
    log = (LoggingService) support.getServiceBroker().getService(this, LoggingService.class, null);
    cmService = (CMService) support.getServiceBroker().getService(this, CMService.class, null);
  }

  /**
   * DOCUMENT ME!
   *
   * @param config DOCUMENT ME!
   *
   * @throws ServletException DOCUMENT ME!
   */
  public void init(ServletConfig config) throws ServletException {
    super.init(config);
    try {
      AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
      configParser = (ConfigParserService) support.getServiceBroker().getService(this, ConfigParserService.class, null);
          return null;
        }
      });
      blackboardService = (BlackboardService) support.getServiceBroker().getService(this, BlackboardService.class, null);
    } catch (RuntimeException e) {
      if (log.isErrorEnabled()) {
        log.error("Unable to initialize servlet: " + e.toString());
        e.printStackTrace();
      }

      throw e;
    }
  }


  /**
   * DOCUMENT ME!
   *
   * @param req DOCUMENT ME!
   * @param res DOCUMENT ME!
   *
   * @throws ServletException DOCUMENT ME!
   * @throws IOException DOCUMENT ME!
   */
  public void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
    String pkcs = null;
    String type = null;
    final String CA_DN_name = (String) req.getParameter("dnname");


    //String domain = null;
    //String data;
    if (log.isDebugEnabled()) {
      log.debug("Received a certificate signing request");
    }

    ByteArrayInputStream bytestream = null;
    PrintStream printstream = new PrintStream(res.getOutputStream());

    //res.setContentType("text/html");
    //  PrintWriter out=res.getWriter();

    try {
      //domain = CertificateUtility.getX500Domain(CA_DN_name, true, ',', true);
      byte[] bytedata = null;

      if ((CA_DN_name == null) || (CA_DN_name == "")) {
        printstream.print("Error ---Unknown  type CA dn name :");
        printstream.flush();
        printstream.close();
        return;
      }

      try {
        /*
           String aDomain = null;
           if( (domain != null) && (domain != ""))  {
             aDomain = domain;
           }
         */
        AccessController.doPrivileged(new PrivilegedAction() {
          public Object run() {
        signer = (CertificateManagementService) support.getServiceBroker().getService(new CertificateManagementServiceClientImpl(CA_DN_name), CertificateManagementService.class, null);
            return null;
          }
        });
        requirePending = configParser.getCaPolicy(CA_DN_name).requirePending;
        if(log.isDebugEnabled()){
        	log.debug("Use Configuration Manager:" + requirePending);
        }
      } catch (Exception exp) {
        printstream.print("Error ---" + exp.toString());
        printstream.flush();
        printstream.close();
        return;
      }

      if (signer == null) {
        printstream.print("Error --- Unable to get CertificateManagementService for" + CA_DN_name);
        printstream.flush();
        printstream.close();
        return;
      }

      type = req.getParameter("pkcs");
      if ((type == null) || (type == "")) {
        printstream.print("Error --- Unknown pkcs type:");
        printstream.flush();
        printstream.close();
        return;
      }

      pkcs = (String) req.getParameter("pkcsdata");

      String replyformat = (String) req.getParameter("replyformat");
      if (replyformat == null) {
        replyformat = "text";
      }

      boolean replyhtml = replyformat.equalsIgnoreCase("html");
      if (replyhtml) {
        printstream.println("<html>");
      }

      if (log.isDebugEnabled()) {
        log.debug("Replying with " + replyformat);
      }


      try {
        if (type.equalsIgnoreCase("pkcs7")) {
          bytedata = pkcs.getBytes();
          bytestream = new ByteArrayInputStream(bytedata);
          signer.processX509Request(printstream, (InputStream) bytestream);

        } else if (type.equalsIgnoreCase("pkcs10")) {
          bytedata = pkcs.getBytes();
          bytestream = new ByteArrayInputStream(bytedata);
          boolean agentRequest = false;
          boolean nodeRequest = false;
          if(requirePending){
            agentRequest =this.isTypeRequest(CertificateCacheConstants.CERT_TITLE_AGENT, pkcs, signer);
          	nodeRequest=this.isTypeRequest(CertificateCacheConstants.CERT_TITLE_NODE, pkcs, signer);
          }
          if (log.isDebugEnabled()) {
            log.debug("Agent Request:" + agentRequest + "  , Node request:" + nodeRequest);
          }

          if (replyhtml) {
            String reply = null;
            if (agentRequest) {
              reply = this.processSignRequestForAgent(req, signer, true);
            } else {
              reply = signer.processPkcs10Request((InputStream) bytestream, true);
            }


            // is it pending? then display pending msg
            String strStat = "status=";
            int statindex = reply.indexOf(strStat);
            if (statindex >= 0) {
              // in the pending mode
              statindex += strStat.length();
              int status = Integer.parseInt(reply.substring(statindex, statindex + 1));
              switch (status) {
                case KeyManagementConstants.PENDING_STATUS_PENDING:
                  printstream.println("Certificate is pending for approval.");
                  break;
                case KeyManagementConstants.PENDING_STATUS_DENIED:
                  printstream.println("Certificate is denied by CA.");
                  break;
                default:
                  printstream.println("Unknown certificate status:" + status);
              }
            } else {
              printstream.print(reply);
            }
          } else {
            String reply = null;
            if (agentRequest) {
              reply = this.processSignRequestForAgent(req, signer, false);
            } else {
              reply = signer.processPkcs10Request((InputStream) bytestream, false);

              if (log.isDebugEnabled()) {
                log.debug("Reply:" + reply);
              }

              if (nodeRequest) {
                this.processSignedNodeCert(pkcs, signer);
              }
            }

            printstream.print(reply);
          }
        } else {
          printstream.print("Error ----Got a wrong parameter for type" + type);
        }

        if (replyhtml) {
          printstream.println("</html>");
        }
      } catch (Exception exp) {
        if (log.isDebugEnabled()) {
          log.debug("Caught an exception when trying to sign: ", exp);
        }


        printstream.print("Error ------" + exp.toString());
      } finally {
        printstream.flush();
        printstream.close();
      }
    } catch (Exception e1) {
      printstream.print("Error ------" + e1.toString());
      printstream.flush();
      printstream.close();
    }
  }


  /**
   * DOCUMENT ME!
   *
   * @param req DOCUMENT ME!
   * @param res DOCUMENT ME!
   *
   * @throws ServletException DOCUMENT ME!
   * @throws IOException DOCUMENT ME!
   */
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
    if (log.isDebugEnabled()) {
      log.debug("+++++ Certificate signing request: ");
      log.debug("method:" + req.getMethod());
      log.debug("authType:" + req.getAuthType());
      log.debug("pathInfo:" + req.getPathInfo());
      log.debug("query:" + req.getQueryString());
    }

    res.setContentType("text/html");
    PrintWriter out = res.getWriter();

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate Signing request </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2> Certificate Signing Request</H2>");
    out.println("<table>");
    out.println("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");
    //out.println("<tr ><td colspan=\"3\">");
    //out.println("Domain : <input name=\"domain\" type=\"text\" value=\"\">");
    //out.println(" <br> <br></td></tr>");
    out.println("<tr ><td colspan=\"3\">");

    // CA
    caDNs = configParser.getCaDNs();
    out.println("Select CA: <select id=\"dnname\" name=\"dnname\">");
    for (int i = 0; i < caDNs.length; i++) {
      out.println("<option value=\"" + caDNs[i].toString() + "\">" + caDNs[i].toString() + "</option>");
    }

    out.println("</select>");

    //out.println("DN for CA <input name=\"dnname\" type=\"text\" value=\"\">");
    out.println(" <br> <br></td></tr>");
    out.println("<tr ><td colspan=\"3\">");
    out.println("<textarea name=\"pkcsdata\" rows=10 cols=80 ></textarea><br>");
    out.println("</td></tr>");
    out.println("<tr><td>Type :</td>");
    out.println("<td>");
    out.println("<input name=\"pkcs\" type=\"radio\" value=\"pkcs7\">pkcs7</input>&nbsp;&nbsp;&nbsp;");
    out.println("<input name=\"pkcs\" type=\"radio\" value=\"pkcs10\">pkcs10</input>");
    // to distinguish between input from browser and from program
    out.println("<input name=\"replyformat\" type=\"hidden\" value=\"html\"></input>");
    out.println("<br></td><td></td>");
    out.println("</tr><tr><td></td><td><br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");
    out.println("<input type=\"reset\"></td><td></td></tr>");
    out.println("</form></table>");
    out.println("</body></html>");
    out.flush();
    out.close();
  }


  /**
   * Process sign request for an agent. If the node signature is verified,  a
   * CMRequest is sent to the CM Agent
   *
   * @param req
   * @param signer CertificateManagementService
   *
   * @return reply to send to the client
   */
  private String processSignRequestForAgent(HttpServletRequest req, CertificateManagementService signer, boolean html) {
    String reply = "status=";
    int status = KeyManagementConstants.PENDING_STATUS_PENDING;
    String nodeSignature = req.getParameter("nodeSignature");
    String nodeName = req.getParameter("node");
    String agent = "";
    String pkcs = (String) req.getParameter("pkcsdata");
    String agentName = this.getCNFromRequest(pkcs, signer);
    try {
      SignedObject signedObject = null;
      if ((nodeSignature == null) || (nodeName == null)) {
        status = KeyManagementConstants.PENDING_STATUS_DENIED;
      } else {
        String decoded = "";
        BASE64Decoder decoder = new BASE64Decoder();
        ByteArrayOutputStream decodedStream = new ByteArrayOutputStream();
        decoder.decodeBuffer(new ByteArrayInputStream(nodeSignature.getBytes()), decodedStream);
        byte[] objectData = decodedStream.toByteArray();
        ByteArrayInputStream bais = new ByteArrayInputStream(objectData);
        ObjectInputStream in = null;
        try {
          // stream closed in the finally
          in = new ObjectInputStream(bais);
          signedObject = (SignedObject) in.readObject();

        } catch (ClassNotFoundException ex) {
          if (log.isErrorEnabled()) {
            log.error("Error deserializing signed object", ex);
          }
        } catch (IOException ex) {
        } finally {
          try {
            if (in != null) {
              in.close();
            }
          } catch (IOException ex) {
            // ignore
          }
        }

        //Verify signed Object
        if (log.isDebugEnabled()) {
          log.debug("Getting Node:" + nodeName + " from local cache");
        }

        X509Certificate nodeCert = (X509Certificate) this.nodeCertMap.get(nodeName.trim());


        if (nodeCert != null) {
          PublicKey publicKey = nodeCert.getPublicKey(); 
          Signature signature = Signature.getInstance("SHA1withRSA");
          if (signedObject.verify(publicKey, signature)) {
            //Query blackboard
            blackboardService.openTransaction();
            Collection cmResponses = blackboardService.query(cmResponsePredicate(nodeName.trim(), agentName));
            if (cmResponses.size() == 0) {
              if (log.isDebugEnabled()) {
                log.debug("No CM Responses for this agent(" + agentName + ") request");
              }
            } else {
              Iterator responses = cmResponses.iterator();
              while (responses.hasNext()) {
                SharedDataRelay sdr = (SharedDataRelay) responses.next();
                CMMessage responseMessage = (CMMessage) sdr.getResponse();
                VerifyResponse response = (VerifyResponse) responseMessage.getResponse();
                blackboardService.publishRemove(sdr);
                if (response.getValidRequest()==false) {
                  if (log.isDebugEnabled()) {
                    log.debug("Found invalid reply for " + agentName + " from CM");
                  }

                  status = KeyManagementConstants.PENDING_STATUS_DENIED;
                } else {
                  byte[] bytedata = pkcs.getBytes();
                  ByteArrayInputStream bytestream = new ByteArrayInputStream(bytedata);
                  blackboardService.closeTransaction();
                  if (log.isDebugEnabled()) {
                    log.debug("Found valid reply for " + agentName + " from CM");
                  }

                  return signer.processPkcs10Request((InputStream) bytestream, html);
                }
              }
            }

            blackboardService.closeTransaction();


          } else {
            if (log.isDebugEnabled()) {
              log.debug("Signed object not valid");
            }

            status = KeyManagementConstants.PENDING_STATUS_DENIED;
          }
        } else {
          if (log.isWarnEnabled()) {
            log.warn("Could not find Node Cert to verify agent sign request");
          }
        }
      }
    } catch (Exception exception) {
      if (log.isErrorEnabled()) {
        log.error("Error processing agent request for signing", exception);
      }
    }

   reply = reply + status;

    if (status == KeyManagementConstants.PENDING_STATUS_PENDING) {
      if (log.isDebugEnabled()) {
        log.debug("Sending CMRequest to Configuration Manager for " + agentName + " to be added to " + nodeName);
      }

      if (cmService == null) {
      	log.error("No Config Manager service available");
        // Service should not be started by this module
      	// the provider should have a component to start itself
        //support.getServiceBroker().addService(CMService.class, new CMServiceProvider(support.getServiceBroker()));
      	return reply;
      }

      VerifyAgentAddRequest cmRequest = new VerifyAgentAddRequest(nodeName.trim(), agentName);
      blackboardService.openTransaction();
      cmService.sendMessage(cmRequest, blackboardService);
      blackboardService.closeTransaction();
    }

    return reply;
  }


  /**
   * Unary Predicate for getting Configuration Manager data on blackboard for
   * an agent sign request
   *
   * @param node
   * @param agent
   *
   * @return
   */
  private UnaryPredicate cmResponsePredicate(final String node, final String agent) {
    return new UnaryPredicate() {
        public boolean execute(Object o) {
          if (o instanceof SharedDataRelay) {
            SharedDataRelay sdr = (SharedDataRelay) o;
            if (sdr.getContent() instanceof CMMessage && sdr.getResponse() instanceof CMMessage) {
              CMMessage response = (CMMessage) sdr.getResponse();
              CMMessage request = (CMMessage) sdr.getContent();
              if (request.getRequest() instanceof VerifyAgentAddRequest) {
                VerifyAgentAddRequest vaar = (VerifyAgentAddRequest) request.getRequest();
                if ((agent != null) && (node != null) && (vaar.getAgent() != null) && (vaar.getAddToNode() != null)) {
                  return (response != null) && vaar.getAgent().equals(agent) && vaar.getAddToNode().equals(node);
                }
              }

              return true;
            }
          }

          return false;
        }
      };
  }


  /**
   * Whether PKCS10 Request is for a type of component
   *
   * @param type Type constant for a certificate type
   * @param request Original PKCS10 String
   * @param signer CertificateManagementService
   *
   * @return If request is for a specified type of component
   */
  private boolean isTypeRequest(String type, String request, CertificateManagementService signer) {
    boolean isType = false;
    try {
      byte[] bytedata = request.getBytes();
      ByteArrayInputStream bytestream = new ByteArrayInputStream(bytedata);
      ArrayList requests = signer.getSigningRequests(bytestream);
      for (int i = 0; i < requests.size(); i++) {
        PKCS10 pkcs10Request = (PKCS10) requests.get(i);
        String title = CertificateUtility.findAttribute(pkcs10Request.getSubjectName().getName(), "t");
        if ((title != null) && title.equals(type)) {
          isType = true;
          break;

        }
      }
    } catch (Exception e) {
      if (log.isErrorEnabled()) {
        log.error("Error checking type of signing request", e);
      }
    }

    return isType;
  }


  private String getCNFromRequest(String request, CertificateManagementService signer) {
    String name = null;
    byte[] bytedata = request.getBytes();
    ByteArrayInputStream bytestream = new ByteArrayInputStream(bytedata);
    ArrayList requests = null;
    try {
      requests = signer.getSigningRequests(bytestream);
    } catch (Exception e) {
      if (log.isErrorEnabled()) {
        log.error("Error getting CN from request", e);

      }

      return name;
    }

    for (int i = 0; i < requests.size(); i++) {
      PKCS10 pkcs10Request = (PKCS10) requests.get(i);
      try {
        return pkcs10Request.getSubjectName().getCommonName();
      } catch (Exception e) {
        if (log.isErrorEnabled()) {
          log.error("Error getting CN from request", e);
        }
      }
    }

    return name;
  }


  /**
   * Add the signed node certificate to the local node cert cache
   *
   * @param request The original PCK10 Request
   * @param signer CertificateManagementService
   */
  private void processSignedNodeCert(String request, CertificateManagementService signer) {
    

    try {
      byte[] bytedata = request.getBytes();
      ByteArrayInputStream bytestream = new ByteArrayInputStream(bytedata);
      ArrayList requests = signer.getSigningRequests(bytestream);

      // Loop through each request and sign it.
      Iterator iter = requests.iterator();
      while (iter.hasNext()) {
        PKCS10 req = (PKCS10) iter.next();
        X509Certificate cert = (X509Certificate) signer.signX509Certificate(req);
        //add to local cache
        if (log.isDebugEnabled()) {
          log.debug("Adding Cert to cache:" + req.getSubjectName().getCommonName());
        }

        this.nodeCertMap.put(req.getSubjectName().getCommonName().trim(), cert);


      }
    } catch (Exception e) {
      if (log.isErrorEnabled()) {
        log.error("Error adding node cert to local cache", e);
      }
    }
  }


  /**
   * DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  public String getServletInfo() {
    return ("Accepts signing request and returns signed certificate");
  }


  /**
   * Blank implementation for Blackboard Client
   *
   * @return DOCUMENT ME!
   */
  public String getBlackboardClientName() {
    // TODO Auto-generated method stub
    return this.getClass().getName();
  }


  /**
   * Blank implementation for Blackboard Client
   *
   * @return DOCUMENT ME!
   */
  public long currentTimeMillis() {
    // TODO Auto-generated method stub
    return 0;
  }

  private class CertificateManagementServiceClientImpl implements CertificateManagementServiceClient {
    private String caDN;

    public CertificateManagementServiceClientImpl(String aCaDN) {
      caDN = aCaDN;
    }

    public String getCaDN() {
      return caDN;
    }
  }
}
