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
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.util.Enumeration;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.certauthority.CertificateResponse;
import org.cougaar.core.security.crypto.Base64;
import org.cougaar.core.security.crypto.KeyManagementConstants;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.service.LoggingService;

import sun.security.pkcs.PKCS10;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;
import sun.security.x509.X509Key;

public class BrowserSigningRequest
  extends  HttpServlet
{
  private CertificateManagementService signer;
  private SecurityServletSupport support;
  private ConfigParserService configParser = null;
  private LoggingService log;
  private X500Name[] caDNs = null;

  private static final int BROWSER_NETSCAPE_DEFAULT   = 1;
  private static final int BROWSER_EXPLORER_DEFAULT   = 2;
  private static final int BROWSER_EXPLORER_5         = 3;
  private static final int BROWSER_EXPLORER_6         = 4;

  public BrowserSigningRequest(SecurityServletSupport support) {
    if (support == null) {
      throw new IllegalArgumentException("Support services null");
    }
    this.support = support;
    log = (LoggingService)
	support.getServiceBroker().getService(this,
	LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
    super.init(config);
    try {
      AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
      configParser = (ConfigParserService)
            support.getServiceBroker().getService(this, ConfigParserService.class, null);
          return null;
    }
      });
    }
    catch (RuntimeException e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to initialize servlet: " + e.toString());
	e.printStackTrace();
      }
      throw e;
    }
  }

  private X500Name getUserName(String userid,
			       String emailAddress,
			       String caDN)
    throws IOException {
    X500Name caName = new X500Name(caDN);
    StringBuffer userDN = new StringBuffer();
    if (log.isDebugEnabled()) {
      log.debug("User info:" + userid + " - " + emailAddress);
    }
    if (userid != null) {
      userDN.append("cn=").append(userid);
    }
    if (emailAddress != null) {
      if (userid != null) {
	userDN.append(", ");
      }
      // E-mail address OID is 1.2.840.113549.1.9.1
      userDN.append("1.2.840.113549.1.9.1=").append(emailAddress);
    }
    String attrs[][] = new String[][] {
      { caName.getOrganizationalUnit(), "ou" },
      { caName.getOrganization(), "o" },
      { caName.getLocality(), "l" },
      { caName.getState(), "st" },
      { caName.getCountry(), "c" }
    };
    for (int i = 0; i < attrs.length; i++) {
      if (attrs[i][0] != null) {
        userDN.append(',').append(attrs[i][1]).append('=').append(attrs[i][0]);
      } // end of if (attrs[i][0] != null)
    } // end of for (int i = 0; i < attrs.length; i++)
    X500Name userName = new X500Name(userDN.toString());
    if (log.isDebugEnabled()) {
      log.debug(userName.toString());
    }
    return userName;
  }

  private PKCS10 getCertReq(String userid,
			    String emailAddress, 
                            String b64PubKey, String caDN) 
    throws IOException, NoSuchAlgorithmException,CertificateEncodingException {
    byte[] derEnc = Base64.decode(b64PubKey.toCharArray());
    DerValue der = new DerValue(derEnc);
    DerValue spki = der.data.getDerValue();
    if (spki.tag != 48) {
      log.debug("Browser certificate is not valid -- invalid SubjectPublicKeyInfo");
      return null;
    } // end of if (spki.tag != 48)
    
    PublicKey pubKey = X509Key.parse(spki.data.getDerValue());
    //AlgorithmId algorithmid = AlgorithmId.get(pubKey.getAlgorithm());
    
    // FIXME: I should verify the signature, but I'm a little lazy right now
//     String challenge = spki.data.getIA5String();

    X500Name user = getUserName(userid, emailAddress, caDN);
    return new MyPKCS10(pubKey, user);
  }

  private void sendCertResponse(CertificateResponse cr, HttpServletResponse resp,
                                int browserType) 
    throws IOException, CertificateEncodingException {
    boolean multipart = false;
    long boundary = System.currentTimeMillis();
    PrintWriter out = resp.getWriter();
    if (cr.cert != null) {
      multipart = true;
      byte[] encoded = cr.cert.getEncoded();
      char[] b64 = Base64.encode(encoded);
      StringBuffer certBuf = new StringBuffer();
      certBuf.append("-----BEGIN CERTIFICATE-----\n");
      certBuf.append(b64);
      certBuf.append("\n-----END CERTIFICATE-----\n");
      String textCert = certBuf.toString();
      resp.reset();
      switch (browserType) {
      case BROWSER_EXPLORER_5:
      case BROWSER_EXPLORER_6:
      case BROWSER_EXPLORER_DEFAULT:
        resp.setContentType("application/x-x509-user-cert");
        resp.setHeader("Content-Disposition","inline; filename=\"user.cer\"");
	break;
      case BROWSER_NETSCAPE_DEFAULT:
      default:
        resp.setContentType("multipart/x-mixed-replace;boundary=" + boundary);
        out.println("--" + boundary);
        out.println("Content-type: application/x-x509-user-cert");
        out.println("Content-length: " + textCert.length());
        out.println();
      } // end of switch
      out.print(textCert);
      switch (browserType) {
      case BROWSER_EXPLORER_5:
      case BROWSER_EXPLORER_6:
      case BROWSER_EXPLORER_DEFAULT:
        return;
      }
      out.println("--" +boundary);
      out.println("Content-type: text/html");
      out.println();
    } else {
      resp.setContentType("text/html");
    } // end of if (resp.cert != null)else
    out.println("<html>");
    out.println("<head><title>Browser Certificate Signing Response</title></head>");
    out.println("<body>");
    String status;
    switch (cr.status) {
    case KeyManagementConstants.PENDING_STATUS_APPROVED:
      status = "Your certificate has been approved and loaded into your browser";
      break;
    case KeyManagementConstants.PENDING_STATUS_PENDING:
      status = "Certificate is pending for approval.";
      break;
    case KeyManagementConstants.PENDING_STATUS_DENIED:
      status = "Certificate is denied by CA.";
      break;
    case KeyManagementConstants.PENDING_STATUS_NEW:
      status = "Certificate has been sent to the CA for approval.";
      break;
    default:
      status = "Error getting the status.";
      break;
    } // end of switch (resp.status)
    out.println(status);
    out.println("</body></html>");
    if (multipart) {
      out.println("--" + boundary + "--");
    } // end of if (multipart)
  }

  public void sendError(HttpServletResponse res, String message) throws IOException {
    res.setContentType("text/html");
    PrintWriter out = res.getWriter();
    out.println("<html><body><h1>Error</h1>");
    out.println(message);
    out.println("</body></html>");
  }

  public void doPost (HttpServletRequest req, HttpServletResponse res)
    throws ServletException,IOException
  {
    if (log.isDebugEnabled()) {
      log.debug("Received a browser certificate signing request");
    }
    int browserType = getBrowserType(req.getHeader("user-agent"));
    String base64PubKey = req.getParameter("SPKAC");
    String userId = req.getParameter("userid");
    String email = req.getParameter("email");
    String caDN = req.getParameter("dnname");

    if (log.isDebugEnabled()) {
      log.debug("userid: " + userId + " - email:" + email);
    }

    try {
      PKCS10 certReq;
      if (base64PubKey != null) {
	if (log.isDebugEnabled()) {
	  log.debug("Creating request using certificate");
	}
        certReq = getCertReq(userId, email, base64PubKey, caDN);
      } else {
	if (log.isDebugEnabled()) {
	  log.debug("Creating request using PKCS data");
	}
        certReq = MyPKCS10.createPKCS10(req.getParameter("pkcsdata"));
      } // end of else
      

      if (caDN == null || caDN.length() == 0) {
        if (log.isDebugEnabled()) {
          log.debug("Error -- Unknown CA dn name: " + caDN);
        } // end of if (log.isDebugEnabled())
        
	sendError(res,"Error ---Unknown  type CA dn name " + caDN);
	return;
      }
      try  {
	signer =
	  (CertificateManagementService)support.getServiceBroker().getService(
	    new CertificateManagementServiceClientImpl(caDN),
	    CertificateManagementService.class, null);
      } catch (Exception exp)  {
        log.debug("Error signing browser certificate", exp);
        sendError(res,"Error ---" + exp.toString());
	return;
      }

      try  {
        CertificateResponse certResp = signer.processPkcs10Request(certReq);

        //sendCertResponse(certResp, res, base64PubKey == null);
	sendCertResponse(certResp, res, browserType);
      }
      catch (Exception  exp)  {
        log.debug("Caught an exception when trying to sign: ", exp);
        sendError(res,"Error ------" + exp.toString());
        return;
      }
    }
    catch (Exception e1) {
      log.debug("Error when processing browser signing request", e1);
      sendError(res,"Error when processing request: " + e1);
    }
  }

  private int getBrowserType(String userAgent) {
    int browserType = BROWSER_NETSCAPE_DEFAULT;
    if (userAgent != null) {
      if (userAgent.indexOf("MSIE 6") != -1)
	browserType = BROWSER_EXPLORER_6;
      else if (userAgent.indexOf("MSIE 5") != -1)
	browserType = BROWSER_EXPLORER_5;
      else if (userAgent.indexOf("MSIE") != -1)
	browserType = BROWSER_EXPLORER_DEFAULT;
    }
    log.debug("Browser type:" + browserType);
    return browserType;
  }

  protected void doGet(HttpServletRequest req,
		       HttpServletResponse res)
    throws ServletException, IOException  {
    Enumeration en = req.getParameterNames();
    while (en.hasMoreElements()) {
      log.debug("Param name:" + (String) en.nextElement());
    }
    if (req.getParameter("vbscript") != null) {
      vbScript(res);
      return;
    } // end of if (req.getParameter("vbscript") != null)
    
    if (log.isDebugEnabled()) {
      log.debug("+++++ Certificate signing request: ");
      log.debug("method:" + req.getMethod());
      log.debug("authType:" + req.getAuthType());
      log.debug("pathInfo:" + req.getPathInfo());
      log.debug("query:" + req.getQueryString());
    }

    int browserType = getBrowserType(req.getHeader("user-agent"));
    res.setContentType("text/html");
    PrintWriter out=res.getWriter();

    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate Manager</title>");
    String onSubmit = "";
    switch (browserType) {
    case BROWSER_EXPLORER_5:
    case BROWSER_EXPLORER_6:
    case BROWSER_EXPLORER_DEFAULT:
      out.println("<script type=\"text/vbscript\" src=\"BrowserSigningRequest?vbscript=true\"></script>");
      onSubmit = "onSubmit=\"myenroll.CreateP10()\"";
    } // end of switch
    
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Manual User Enrollment</H2>");
    out.println("Use this form to submit a request for a personal certificate. After you click the "
		+ "submit button, your request will be submitted to the Certificate Authority.</br>"
		+ "When the certificate authority has approved your request, you will be able "
		+ "to install your certificate in your browser</br>"
		+ "and use it as a client certificate or to send and receive encrypted e-mail.</br>"
		+ "User ID format: \"DomainName-UserName\"</br>");
    switch (browserType) {
    case BROWSER_EXPLORER_5:
    case BROWSER_EXPLORER_DEFAULT:
      out.println("<object classid=\"clsid:43F8F289-7A20-11D0-8F06-00C04FC295E1\" " +
                  "codebase=\"file:///WINDOWS/SYSTEM32/xenroll.dll\" id=\"cenroll\">" +
                  "This isn't internet explorer! You can't create a certificate " + 
                  "with this browser</object>");
      break;
    case BROWSER_EXPLORER_6:
      out.println("<object classid=\"clsid:127698E4-E730-4E5C-A2b1-21490A70C8A1\" " +
                  "codebase=\"xenroll.dll\" id=\"cenroll\">" +
                  "This isn't internet explorer! You can't create a certificate " + 
                  "with this browser</object>");
    } // end of switch
    out.println("<form name=\"MyForm\" id=\"MyForm\" action=\"BrowserSigningRequest\" method =\"post\" " + onSubmit + ">");
    out.println("<table>");
    out.println("<tr><td align=right>");

    // CA
    out.println("Select CA:</td><td align=left><select id=\"dnname\" name=\"dnname\">");

    caDNs = configParser.getCaDNs();
    for (int i = 0 ; i < caDNs.length ; i++) {
      out.println("<option value=\"" + caDNs[i].toString() + "\">" 
		  + caDNs[i].toString() + "</option>");
    }
    out.println("</select>");

    out.println("</td></tr>");
    out.println("<tr><td align=right>User Id</td><td align=left><input type=text name=userid></td></tr>");
    out.println("<tr><td align=right>E-mail</td><td align=left><input type=text name=email></td></tr>");
    out.println("<tr><td align=right>");
    long challenge = (long)(Math.random() * Long.MAX_VALUE);
    switch (browserType) {
    case BROWSER_EXPLORER_5:
    case BROWSER_EXPLORER_6:
    case BROWSER_EXPLORER_DEFAULT:
      out.print("Cryptographic Service Provider</td><td align=left>" +
                "<select name=cspName id=cspName></select>" + 
                "<input type=hidden name=pkcsdata>" + 
                "<input type=hidden name=pkcs value=pkcs10>" + 
                "<input type=hidden name=replyformat value=html>");
      break;
    default:
      out.print("Select the key size:</td><td align=left><keygen name=SPKAC challenge=");
      out.print(challenge);
      out.println(">");      
    } // end of switch
    out.println("</td></tr>");
    switch (browserType) {
    case BROWSER_NETSCAPE_DEFAULT:
      out.println("<tr><td colspan=2>Please note that the Schlumberger " +
                  "<b>smart cards only support 1024 bit keys</b>, so please " +
                  "select 1024 bits if you are using a smart card.</td></tr>");
    } // end of switch
    out.println("<tr><td align=right><input type=\"submit\" value=\"Get Certificate\">");
    out.println("<td align=left><input type=\"reset\"></td></tr>");
    out.println("</table>");
    out.println("<input type=hidden name=challenge value=" + challenge + ">");
    switch (browserType) {
    case BROWSER_EXPLORER_5:
    case BROWSER_EXPLORER_6:
    case BROWSER_EXPLORER_DEFAULT:
      out.println("<script type=\"text/vbscript\">");
      out.println("<!--");
      out.println("Set myenroll=new Enroll");
      out.println("myenroll.FindProviders");
      out.println("' -->");
      out.println("</script>");
      out.println("<noscript>");
      out.println("<p class=\"errmsg\">VBScript must be enabled!</p>");
      out.println("</noscript>");
    } // end of if (isIE)
    out.println("</form>");
    out.println("</body></html>");
    out.flush();
    out.close();
  }

  private void vbScript(HttpServletResponse resp) throws IOException {
    resp.setContentType("text/vbscript");
    PrintWriter out = resp.getWriter();
    log.debug("vbScript()");
    out.print("Option Explicit\n" +
              "\n" +
              "Class Enroll\n" +
              "  Private Form\n" +
              "  Private DN\n" +
              "\n" +
              "  Private Sub Class_Initialize()\n" +
              "    Set Form = Document.MyForm\n" +
              "  End Sub\n" +
              "\n" +
              "  Public Sub FindProviders()\n" +
              "    Dim i, j, cspOption, csp, DefaultKeySize\n" +
              "    Const enumFlags = 0\n" +
              "    On Error Resume Next\n" +
              "\n" +
              "    i = 0\n" +
              "    j = 1\n" +
              "    DefaultKeySize = 0\n" +
              "    cenroll.providerType = 1\n" +
              "    Do\n" +
              "      csp = \"\"\n" +
              "      csp = cenroll.enumProviders(i, enumFlags)\n" +
              "      If Len(csp) = 0 Then\n" +
              "        Exit Do\n" +
              "      End If\n" +
              "      set cspOption = document.createElement(\"option\")\n" +
              "      cspOption.text = csp\n" +
              "      cspOption.value = csp\n" +
              "      Form.cspName.add(cspOption)\n" +
              "      i = i + 1\n" +
              "      j = j + 1\n" +
              "    Loop\n" +
              "    Form.cspName.selectedIndex = DefaultKeySize\n" +
              "  End Sub\n" +
              "\n" +
              "  Private Sub FieldErr(f)\n" +
              "    f.Focus\n" +
              "    Alert \"Error: \" & f.id & \" is empty or illegal\"\n" +
              "  End Sub\n" +
              "\n" +
              "  Public Function CreateP10()\n" +
              "    Dim keyprov, key, prov, pkcs10data, GenKeyFlags\n" +
              "    Const CRYPT_EXPORTABLE=1\n" +
              "    Const CRYPT_USER_PROTECTED=2\n" +
              "    Const usage = \"\"\n" +
              "    CreateP10 = False\n" +
              "    If ChangeDN = False Then\n" +
              "      Exit Function\n" +
              "    End If\n" +
              "    prov = Form.cspName.value\n" +
              "    GenKeyFlags = 0\n" +
              "    cenroll.providerName = prov\n" +
              "    cenroll.EnableT61DNEncoding = True\n" +
              "    On Error Resume Next\n" +
              "    pkcs10data = cenroll.createPKCS10(DN, usage)\n" +
              "    If pkcs10data = Empty Then\n" +
              "      CreateP10 = False\n" +
              "      Alert \"Error \" & Hex(Err) & \": Your credentials could not be generated.\"\n" +
              "      Exit Function\n" +
              "    End If\n" +
              "    CreateP10 = True\n" +
              "    Form.pkcsdata.value = pkcs10data\n" +
              "  End Function\n" +
              "\n" +
              "  Private Function AddToDN(name, value)\n" +
              "    AddToDN = True\n" +
              "    If ((name = \"T\") or (name = \"t\") or (name = \"CN\") or (name = \"cn\")) Then\n" +
              "      Exit Function\n" +
              "    End If\n" +
              "    DN = DN & \",\" & name & \"=\" & value\n" +
              "  End Function\n" +
              "\n" +
              "  Public Function ChangeDN()\n" +
              "    Dim val, name, value, eq, com, c, i\n" +
              "    ChangeDN = True\n" +
              "    DN = \"CN=\" & Form.userid.value\n" +
	      "    If Form.email.value <> Empty Then\n" + 
	      "      DN = DN & \",1.2.840.113549.1.9.1=\" + Form.email.value\n" +
	      "    End If \n" +
              "    val = Form.dnname.value\n" +
              "    com = 0\n" +
              "    For i = 1 to Len(val)\n" +
              "      c = Mid(val, i, 1)\n" +
              "      If c = \" \" and com = i - 1 Then\n" +
              "        com = com + 1\n" +
              "      End If  \n" +
              "      If c = \"=\" Then\n" +
              "        eq = i\n" +
              "      End If  \n" +
              "      If c = \",\" Then\n" +
              "        name = Mid(val, com + 1, eq - com - 1)\n" +
              "        value = Mid(val, eq + 1, i - eq - 1)\n" +
              "        If AddToDN(name, value) = False Then\n" +
              "          rem name=\"foo\"\n" +
              "        End If\n" +
              "        com = i\n" +
              "      End If\n" +
              "    Next\n" +
              "    name = Mid(val, com + 1, eq - com - 1)\n" +
              "    value = Mid(val, eq + 1, i - eq - 1)\n" +
              "    If AddToDN(name,value) = False Then\n" +
              "      rem name=\"foo\"\n" +
              "    End If\n" +
              "  End Function\n" +
              "\n" +
              "End Class\n" +
              "\n" +
              "Dim myenroll\n");
  }
  public String getServletInfo()
  {
    return("Accepts signing request and returns signed certificate");
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

  private static class MyPKCS10 extends PKCS10 {
    X500Name _subject;
    public MyPKCS10(PublicKey pubKey, X500Name subject) {
      super(pubKey);
      _subject = subject;
    }

    /**
     * Create a PKCS10 object from a Base-64 encoded Certificate Signing Request.
     */
    public static PKCS10 createPKCS10(String b64)
      throws IOException, SignatureException, NoSuchAlgorithmException {
      byte bytes[] = Base64.decode(b64.toCharArray());
      DerInputStream derinputstream = new DerInputStream(bytes);
      DerValue adervalue[] = derinputstream.getSequence(3);
      if(adervalue.length != 3)
        throw new IllegalArgumentException("not a PKCS #10 request");
      bytes = adervalue[0].toByteArray();
      AlgorithmId algorithmid = AlgorithmId.parse(adervalue[1]);
      byte sig[] = adervalue[2].getBitString();
      BigInteger bigint = adervalue[0].data.getBigInteger();
      if(bigint.intValue() != 0) {
        throw new IllegalArgumentException("not PKCS #10 v1");
      }

      X500Name subject = new X500Name(adervalue[0].data);
      PublicKey pubKey = X509Key.parse(adervalue[0].data.getDerValue());
      try {
        Signature signature = Signature.getInstance(algorithmid.getName());
        signature.initVerify(pubKey);
        signature.update(bytes);
        if(!signature.verify(sig))
          throw new SignatureException("Invalid PKCS #10 signature");
        return new MyPKCS10(pubKey, subject);
      } catch(InvalidKeyException invalidkeyexception) {
        throw new SignatureException("invalid key");
      }
    }

    public X500Name getSubjectName() {
      return _subject;
    }
  }
}
