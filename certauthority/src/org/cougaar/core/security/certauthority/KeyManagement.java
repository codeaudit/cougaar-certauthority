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
 


package org.cougaar.core.security.certauthority;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.Base64;
import org.cougaar.core.security.crypto.CertificateCacheConstants;
import org.cougaar.core.security.crypto.CertificateRevocationStatus;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.NodeConfiguration;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.crypto.KeyManagementConstants;
import org.cougaar.core.security.naming.CACertificateEntry;
import org.cougaar.core.security.naming.CertificateEntry;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.CRLCacheService;
import org.cougaar.core.security.services.util.CACertDirectoryService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.DateUtil;
import org.cougaar.core.service.LoggingService;

import sun.security.pkcs.PKCS10;
import sun.security.pkcs.PKCS10Attributes;
import sun.security.pkcs.PKCS7;
import sun.security.provider.X509Factory;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.OIDMap;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/** Certification Authority service
 * The following java properties are necessary:
 * + org.cougaar.security.CA.certpath: set when class used as a standalone CA.
 *     In that case, KeyManagement is instantiated from a servlet.
 *     The property should not be defined if the CA service is instantiated
 *     from Cougaar.
 * + See also org.cougaar.core.security.crypto.ConfParser for other required properties. */


public class KeyManagement  implements CertificateManagementService {

  private KeyRingService keyRing = null;
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;

  private String topLevelDirectory = null;
  private String x509directory = null;
  private CaPolicy caPolicy = null;            // the policy of the CA
  private CryptoClientPolicy cryptoClientPolicy;        // the policy of the Node
  private NodeConfiguration nodeConfiguration;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  private String caDN = null;                  /* the distinguished name of
						* the CA */
  private X509Certificate caX509cert = null;   /* the X.509 certificate
						  of the CA */
  private X500Name caX500Name = null;          // the X.500 name of the CA

  //private CertDirectoryServiceCA caOperations = null;
  private CACertDirectoryService caOperations = null;

  private String role;
  
  private CRLCacheService crlCache = null;

  
/**  KeyManagement constructor
 */
  public KeyManagement(ServiceBroker serviceBroker) {
    this.serviceBroker = serviceBroker;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    if (log == null) {
      throw new RuntimeException("Unable to get logging service");
    }
  }

  /**  Set key management parameters
   * @param aCA_DN       - The distinguished name of the CA
   */
  public void setParameters(String aCA_DN) {
    keyRing = null;
    secprop = null;
    configParser = null;
    topLevelDirectory = null;
    x509directory = null;
    caPolicy = null;
    cryptoClientPolicy = null;
    nodeConfiguration = null;
    caDN = null;
    caX500Name = null;
    caOperations = null;
    role = null;

    caDN = aCA_DN;
    if (log.isInfoEnabled()) {
      log.info("Configuring CA:" + caDN);
    }

    String caCommonName = null;
    try {
      caX500Name = new X500Name(caDN);
      caCommonName = caX500Name.getCommonName();
    }
    catch (java.io.IOException e) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to parse requested CA DN: " + caDN);
      }
      throw new RuntimeException("Unable to parse requested CA DN: " + caDN);
    }

    secprop = (SecurityPropertiesService)
      serviceBroker.getService(
	this,
	SecurityPropertiesService.class,
	null);
    if (secprop == null) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get security properties service.");
      }
      throw new RuntimeException("Unable to get security properties service");
    }

    // Retrieve KeyRing service
    keyRing = (KeyRingService)
      serviceBroker.getService(
	this,
	KeyRingService.class,
	null);
    if (keyRing == null) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get keyring service.");
      }
      throw new RuntimeException("Unable to get keyring service");
    }

    crlCache = (CRLCacheService)
    serviceBroker.getService(this, CRLCacheService.class, null);
    if (crlCache == null) {
      if (log.isWarnEnabled()) {
        log.warn("Unable to get crl cache service.");
      }
      throw new RuntimeException("Unable to get crl cache service");
    }

    configParser = (ConfigParserService)
      serviceBroker.getService(this,
			       ConfigParserService.class,
			       null);
    if (configParser == null) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get policy configuration service.");
      }
      throw new RuntimeException("Unable to get policy configuration service");
    }

    if (log.isDebugEnabled()) {
      if (configParser.isCertificateAuthority()) {
	log.debug("Running as CA");
      }
      else {
	log.debug("Running as Cougaar node");
      }
    }

    nodeConfiguration = new NodeConfiguration(caDN, serviceBroker);

    role = secprop.getProperty(SecurityPropertiesService.SECURITY_ROLE);
    if (role == null && log.isWarnEnabled() == true) {
      log.warn("Role not defined");
    }
    init();
  }

  public void init() {
    if(configParser.isCertificateAuthority()) {
      // Get the CA policy
      caPolicy = configParser.getCaPolicy(caDN);
      if (caPolicy == null) {
	if (log.isWarnEnabled()) {
	  log.warn("Unable to get policy for CA: " + caDN);
	}
	throw new RuntimeException("Unable to get CA policy");
      }
       
                              
      caOperations = (CACertDirectoryService)
	serviceBroker.getService(this,CACertDirectoryService.class, null);
      
      /*
        CertDirectoryServiceRequestor cdsr =
	new CertDirectoryServiceRequestorImpl(caPolicy.ldapURL, caPolicy.ldapType,
        caPolicy.ldapPrincipal, caPolicy.ldapCredential,
        serviceBroker);
        caOperations = (CertDirectoryServiceCA)
	serviceBroker.getService(cdsr, CertDirectoryServiceCA.class, null);
      */
       
      if (caOperations == null) {
	throw new RuntimeException("Unable to communicate with LDAP server");
      }
      //publishCA();
    }
    else{
      // We are a node
      caPolicy = configParser.getCaPolicy("");
      if (caPolicy == null) {
	if (log.isWarnEnabled()) {
	  log.warn("Unable to read policy for " + caDN);
	}
	throw new RuntimeException("Unable to read policy");
      }
      if (log.isDebugEnabled()) {
	log.debug("Running in Cougaar environment");
      }
    }

    if (log.isDebugEnabled()) {
      log.debug("Got Ca policy "+ caPolicy.toString());
    }
    SecurityPolicy[] sp =
      configParser.getSecurityPolicies(CryptoClientPolicy.class);
    cryptoClientPolicy = (CryptoClientPolicy) sp[0];

    if (cryptoClientPolicy == null) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get crypto client policy");
      }
      throw new RuntimeException("Unable to get crypto client policy");
    }

    try {
      List caX509certList = keyRing.findCert(caX500Name.getCommonName());
      if (caX509certList.size() > 0) {
	caX509cert = ((CertificateStatus)caX509certList.get(0)).getCertificate();
      }
    }
    catch (Exception e) {
      throw new RuntimeException("Error: Unable to find CA cert: " + e);
    }

    if (caX509cert == null) {
      if (log.isWarnEnabled()) {
        log.warn("No CA cert found. CA key is not created yet.");
      }
    }
  }


  public synchronized void processX509Request(PrintStream out,
					      InputStream inputstream) {
    Collection c = null;
    if(inputstream == null)
      return;
    try {
      if (log.isDebugEnabled()) {
	log.debug("X.509 Request is : ");
	String s = "";
	while (inputstream.available() > 0) {
	  int len = 256;
	  byte[] bbuf = new byte[len];
	  int read = inputstream.read(bbuf, 0, len);
	  s = s + new String(bbuf, 0, read);
	}
	log.debug(s);
      }
      inputstream.reset();

      // Extract X509 certificates from the input stream
      if(!inputstream.markSupported()) {
	byte abyte0[] = getTotalBytes(new BufferedInputStream(inputstream));
	inputstream = new ByteArrayInputStream(abyte0);
      }
      if(CertificateUtility.isBase64(inputstream)) {
	byte abyte1[] = CertificateUtility.base64_to_binary(inputstream);
	c = CertificateUtility.parseX509orPKCS7Cert(new ByteArrayInputStream(abyte1));
      } else {
	c = CertificateUtility.parseX509orPKCS7Cert(inputstream);
      }

      Iterator i = c.iterator();
      while (i.hasNext()) {
	X509CertImpl clientX509 = (X509CertImpl) i.next();
	// Lookup certificate using DirectoryKeyStore

	if (clientX509 != null) {
	  // Save the X509 reply in a file
	  saveX509Request(clientX509, false);
                  
	  // Publish certificate 
          publishCertificate(clientX509,
                             CertificateUtility.EntityCert,null);
        }
	else {
	  log.warn("Unable to publish Certificate. Certificate is null");
	}
      }
/*
  if (configParser.isCertificateAuthority()) {
  publishCA();
  }
*/
    }
    catch(Exception e) {
      log.error("Unable to process request: ", e);
    }
  }

  /** Process a PKCS10 request:
   * - Get a list of certificate signing requests.
   * - Sign each request with the CA private key.
   * - Save each signed certificate in a local file system.
   * - Publish each signed certificate in an LDAP directory service.
   */
  public synchronized X509Certificate[] processPkcs10Request(InputStream request) {
    ArrayList ar = new ArrayList();
    try {
      if (log.isDebugEnabled()) {
	log.debug("processPkcs10Request");
      }
      // First, get all the PKCS10 requests in an array list.
      ArrayList requests = getSigningRequests(request);

      // Loop through each request and sign it.
      Iterator i = requests.iterator();
      while (i.hasNext()) {
	PKCS10 req = (PKCS10)i.next();
       	X509CertImpl clientX509 = signX509Certificate(req);
	ar.add(clientX509);
	// Save the X509 reply in a file
	saveX509Request(clientX509, false);

        if (configParser.isCertificateAuthority()) {
	  // Publish certificate in LDAP directory
	  if (log.isDebugEnabled()) {
	    log.debug("Publishing cert to LDAP service: " + clientX509.getSubjectDN().getName());
	  }
	  publishCertificate(clientX509,
                             CertificateUtility.EntityCert,null);
/*
  if (configParser.isCertificateAuthority()) {
  publishCA();
  }
*/
	}
      }
    }
    catch (Exception e) {
      log.error("Unable to process request: ", e);
      return null;
    }

    X509Certificate[] reply = new X509Certificate[ar.size()];
    for (int i = 0 ; i < ar.size() ; i++) {
      reply[i] = (X509Certificate)ar.get(i);
    }
    if (log.isDebugEnabled()) {
      log.debug("Reply contains " + ar.size()
                + " certificates");
    }
    return reply;
  }

  /**
   * @param replyInHtml true if the reply is in HTML format. Set to true when the request comes from a browser.
   *
   */
  public synchronized String processPkcs10Request(InputStream request,
                                                  boolean replyInHtml)
    {
      String reply = "";
      if (!caPolicy.requirePending) {
        try {
          X509Certificate[] certs = processPkcs10Request(request);
          //CertificateUtility.base64EncodeCertificates(out, certs);
          for (int i = 0 ; i < certs.length ; i++) {
            reply = reply + CertificateUtility.base64encode(certs[i].getEncoded(),
                                                            CertificateUtility.PKCS7HEADER,
                                                            CertificateUtility.PKCS7TRAILER);
          }

          if (replyInHtml) {
            // convert \n to <br>
            reply = reply.replaceAll("\n", "<br>");
          }
          else {
            reply = URLEncoder.encode(reply, "UTF-8");
          }
          if (log.isDebugEnabled()) {
            log.debug("replyInHtml=" + replyInHtml + "\n"
                      + reply);
          }
        }
        catch (CertificateEncodingException e) {
          if (log.isDebugEnabled()) {
            log.warn("Unable to process PKCS10 request:", e);
          }
        }
        catch (IOException e) {
          if (log.isDebugEnabled()) {
            log.warn("Unable to process PKCS10 request:", e);
          }
        }

        return reply;
      }

      try {
        if (log.isDebugEnabled()) {
          log.debug("processPkcs10Request");
        }
        // First, get all the PKCS10 requests in an array list.
        ArrayList requests = getSigningRequests(request);

        String [] dirlist = new String[3];
        dirlist[1] = nodeConfiguration.getX509DirectoryName(caDN);
        dirlist[2] = nodeConfiguration.getPendingDirectoryName(caDN);
        dirlist[0] = nodeConfiguration.getDeniedDirectoryName(caDN);

        // Loop through each request and sign it.
        Iterator i = requests.iterator();
        while (i.hasNext()) {
          PKCS10 req = (PKCS10)i.next();

          X509CertImpl clientX509 = signX509Certificate(req);
          /* Richard - don't reply yet, otherwise the client installs
           * those certs to keystore
           * Richard -- reply with a status plus the certificate
           * status -
           * 1. success if the certificate is enclosed
           * 2. pending if no certificate and the certificate is saved to
           * the pending/  directory
           * 3. denied if no certificate and the certificate is saved to
           * the denied/  directory
           * 4. if the request has never been issued
           */
          PendingCertCache pendingCache =
            PendingCertCache.getPendingCache(caPolicy.caDnName.getName(), serviceBroker);

          X509CertImpl prevCert = null;
          PublicKey clientPubkey = clientX509.getPublicKey();
          int status = 0;
          for (; status < dirlist.length; status++) {
            prevCert = (X509CertImpl)
              pendingCache.getCertificate(dirlist[status], clientPubkey);
            if (prevCert != null)
              break;
          }

          if (log.isDebugEnabled()) {
            log.debug("Certificate status is: " + status);
          }

          if (status == KeyManagementConstants.PENDING_STATUS_NEW) {
            // Save the X509 reply in a file
            saveX509Request(clientX509, true);
            // from here process as pending
            status = KeyManagementConstants.PENDING_STATUS_PENDING;

            PendingCertCache.addCertificateToList(
              dirlist[2], keyRing.getAlias(clientX509), clientX509);
          }

          //if (replyInHtml) {
          if (status == KeyManagementConstants.PENDING_STATUS_APPROVED) {
            reply = CertificateUtility.base64encode(prevCert.getEncoded(),
                                                    CertificateUtility.PKCS7HEADER,
                                                    CertificateUtility.PKCS7TRAILER);
            // convert \n to <br>
            if (replyInHtml) {
              reply = reply.replaceAll("\n", "<br>");
            }
            else {
              reply = URLEncoder.encode(reply, "UTF-8");
            }
          }
          else {
            reply = "status=" + status;
          }

          /*
            }
            else
            reply = "status=" + status;
          */

        }
      }
      catch (Exception e) {
        log.warn("Unable to process request: ", e);
      }

      return reply;
    }

  /**
   * Create a certificate from the PKCS10 request and sign it if
   * it has been approved.
   *
   * @param pkcs10 The request to use for signing
   * @return The status and certificate if it has been approved.
   */
  public synchronized CertificateResponse processPkcs10Request(PKCS10 req) {
    if (!caPolicy.requirePending) {
      try {
       	X509CertImpl clientX509 = signX509Certificate(req);

	// Save the X509 reply in a file
	saveX509Request(clientX509, false);
       	if (configParser.isCertificateAuthority()) {
          
	  // Publish certificate in LDAP directory
	  if (log.isDebugEnabled()) {
	    log.debug("Publishing cert to LDAP service");
	  }
	  publishCertificate(clientX509,
                             CertificateUtility.EntityCert,null);
/*
  if (configParser.isCertificateAuthority()) {
  publishCA();
  }
*/
	}
        return new CertificateResponse(KeyManagementConstants.PENDING_STATUS_APPROVED, clientX509);
      } catch (Exception e) {
        log.error("Unable to process request: " + e);
        log.debug("exception trace", e);
        return null;
      }
    }

    // Pending request
    try {
      if (log.isDebugEnabled()) {
	log.debug("processPkcs10Request");
      }
      String [] dirlist = new String[3];
      dirlist[1] = nodeConfiguration.getX509DirectoryName(caDN);
      dirlist[2] = nodeConfiguration.getPendingDirectoryName(caDN);
      dirlist[0] = nodeConfiguration.getDeniedDirectoryName(caDN);

      X509CertImpl clientX509 = signX509Certificate(req);
      /* Richard - don't reply yet, otherwise the client installs
       * those certs to keystore
       * Richard -- reply with a status plus the certificate
       * status -
       * 1. success if the certificate is enclosed
       * 2. pending if no certificate and the certificate is saved to
       * the pending/  directory
       * 3. denied if no certificate and the certificate is saved to
       * the denied/  directory
       * 4. if the request has never been issued
       */
      PendingCertCache pendingCache =
        PendingCertCache.getPendingCache(caPolicy.caDnName.getName(), serviceBroker);

      X509CertImpl prevCert = null;
      PublicKey clientPubkey = clientX509.getPublicKey();
      int status = 0;
      for (; status < dirlist.length; status++) {
        prevCert = (X509CertImpl)
          pendingCache.getCertificate(dirlist[status], clientPubkey);
        if (prevCert != null)
          break;
      }

      if (log.isDebugEnabled()) {
        log.debug("Certificate status is: " + status);
      }

      if (status == KeyManagementConstants.PENDING_STATUS_NEW) {
        // Save the X509 reply in a file
        saveX509Request(clientX509, true);
        // from here process as pending
        status = KeyManagementConstants.PENDING_STATUS_PENDING;

        PendingCertCache.
          addCertificateToList(dirlist[2],
                               keyRing.getAlias(clientX509), clientX509);
      }

      if (status != KeyManagementConstants.PENDING_STATUS_APPROVED) {
        clientX509 = null;
      } // end of if (status != PENDING_STATUS_APPROVED)

      return new CertificateResponse(status, clientX509);
    } catch (Exception e) {
      log.warn("Unable to process request", e);
    }

    return null;
  }

  private void saveX509Request(X509CertImpl clientX509, boolean pending)
    throws IOException, CertificateEncodingException, NoSuchAlgorithmException
    {
      if (configParser.isCertificateAuthority()) {
        if (log.isDebugEnabled()) {
          log.debug("Saving X509 certificate:");
        }
        String alias = keyRing.getAlias(clientX509);
        String filepath = null;
        if (pending) {
          filepath = nodeConfiguration.getPendingDirectoryName(caDN);
        }
        else {
          filepath = nodeConfiguration.getX509DirectoryName(caDN);
        }
        filepath += File.separatorChar + alias + ".cer";
        if (log.isDebugEnabled()) {
          log.debug("Saving X509 certificate to: " + filepath);
        }

        File f = new File(filepath);
        f.createNewFile();
        PrintStream out = new PrintStream(new FileOutputStream(f));
        CertificateUtility.base64encode(out, clientX509.getEncoded(),
                                        CertificateUtility.PKCS7HEADER,
                                        CertificateUtility.PKCS7TRAILER);

        out.close();
      }
    }

  public void printPkcs7Request(String filename)
    {
      try {
        FileInputStream is = new FileInputStream(filename);
        X509Factory x509factory = new X509Factory();
        Collection c = x509factory.engineGenerateCertificates(is);
        log.debug(c.toString());
        //BufferedReader is = new BufferedReader(new FileReader(filename));
        //printPkcs7Request(is);
      }
      catch (Exception e) {
        log.warn("Exception: ", e);
      }
    }

  public Collection printPkcs7Request(InputStream inputstream)
    throws CertificateException
    {
      if(inputstream == null)
        throw new CertificateException("Missing input stream");
      try {
        if(!inputstream.markSupported()) {
          byte abyte0[] = getTotalBytes(new BufferedInputStream(inputstream));
          inputstream = new ByteArrayInputStream(abyte0);
        }
        if(CertificateUtility.isBase64(inputstream)) {
          byte abyte1[] = CertificateUtility.base64_to_binary(inputstream);
          return CertificateUtility.parseX509orPKCS7Cert(new ByteArrayInputStream(abyte1));
        } else {
          return CertificateUtility.parseX509orPKCS7Cert(inputstream);
        }
      }
      catch(IOException ioexception) {
        throw new CertificateException(ioexception.getMessage());
      }
    }

  public void printPkcs7Request(BufferedReader bufreader)
    {
      try {
        int len = 2000;     // Size of a read operation
        char [] cbuf = new char[len];
        String sbuf = null;
        while (bufreader.ready()) {
          int read = bufreader.read(cbuf, 0, len);
          sbuf = sbuf + new String(cbuf, 0, read);
        }

        String base64EncodeRequest =
          CertificateUtility.getBase64Block(sbuf,
                                            CertificateUtility.PKCS7HEADER,
                                            CertificateUtility.PKCS7TRAILER);
        byte der[] = Base64.decode(base64EncodeRequest.toCharArray());
        InputStream inputstream = new ByteArrayInputStream(der);
        PKCS7 pkcs7 = new PKCS7(inputstream);
        log.debug("PKCS7: " + pkcs7);
      }
      catch (Exception e) {
        log.warn("Exception: ", e);
      }
    }

  /**
   * Get an array of PKCS10 certificate signing requests.
   * The file contains Base64 encoded signing requests, which are each bounded at
   * the beginning by -----BEGIN NEW CERTIFICATE REQUEST-----, and bounded at the
   * end by -----END NEW CERTIFICATE REQUEST-----.
   */
  public ArrayList getSigningRequests(InputStream reader)
    throws FileNotFoundException, IOException, SignatureException,
    NoSuchAlgorithmException, InvalidKeyException
    {
      int len = 200;     // Size of a read operation
      int ind_start, ind_stop, ind_end;
      byte [] bbuf = new byte[len];
      String sbuf = null;
      ArrayList pkcs10requests = new ArrayList();

      if (log.isDebugEnabled()) {
        log.debug("getSigningRequests");
      }

      while (reader.available() > 0) {
        int read = reader.read(bbuf, 0, len);
        String s = new String(bbuf, 0, read);
        sbuf = sbuf + s;

        // Find header
        ind_start = findLine(sbuf,CertificateUtility.PKCS10HEADER_ARR, 0);
        if (ind_start == -1) {
          // No header was found
          break;
        }

        // Find trailer
        ind_end = findLine(sbuf,CertificateUtility.PKCS10TRAILER_ARR, ind_start);
        if (ind_end == -1) {
          // No trailer was found. Maybe we didn't read enough data?
          // Try to read more data.
          continue;
        }
        ind_stop = sbuf.indexOf(CertificateUtility.PKCS10TRAILER_ARR[0], ind_start);

        // Extract Base-64 encoded request and remove request from sbuf
        String base64pkcs = sbuf.substring(ind_start,ind_stop);
        sbuf = sbuf.substring(ind_end);
        if (log.isDebugEnabled()) {
          log.debug("base64pkcs: " + base64pkcs);
        }

        // Decode request and store it as a DER value
        byte pkcs10DER[] = Base64.decode(base64pkcs.toCharArray());
        //FileOutputStream f = new FileOutputStream("der.cer");
        //f.write(pkcs10DER);
        //f.close();

        // Create PKCS10 object
        PKCS10 pkcs10 = getSigningRequest(pkcs10DER);
        pkcs10requests.add(pkcs10);
      }

      return pkcs10requests;
    }

  private static int findLine(String str, String[] components, int start) {
    for (int i = 0; i < components.length; i++) {
      start = str.indexOf(components[i], start);
      if (start == -1) return -1;
      start += components[i].length();
    }
    return start;
  }

  public ArrayList getSigningRequests(String filename)
    throws FileNotFoundException, IOException, SignatureException,
    NoSuchAlgorithmException, InvalidKeyException
    {
      if (log.isDebugEnabled()) {
        log.debug("PKCS10 file: " + filename);
      }
      FileInputStream is = new FileInputStream(filename);
      return getSigningRequests(is);
    }

  /**
   * Get a PKS10 object from a DER encoded certificate signing request.
   */
  public PKCS10 getSigningRequest(byte[] bytes)
    throws IOException, SignatureException, NoSuchAlgorithmException,
    InvalidKeyException
    {
      PKCS10 request = new PKCS10(bytes);

      if (log.isDebugEnabled()) {
        log.debug("PKCS10 request:" + request.toString());
        // pkcs10Request.print(dbgout);
      }
      return request;
    }

  private Object _lock = new Object();

  private  BigInteger getNextSerialNumber()
    throws FileNotFoundException, IOException
    {
      String serialNbFileName = nodeConfiguration.getNodeDirectory()
        + File.separatorChar + "serialNumber.txt";
      if (log.isDebugEnabled()) {
        log.debug("Serial Number file name: " + serialNbFileName);
      }
      File fserial = new File(serialNbFileName);
      FileWriter fOutSerial = null;
      BigInteger nextSerialNumber = null;
      String serialNbString = null;

      synchronized(_lock) {
	if (!fserial.exists()) {
	  if (log.isDebugEnabled()) {
	    log.debug("Serial Number file (" + serialNbFileName +
		      ") does not exists. Creating...");
	  }
	  //fserial = new File(serialNbFileName);
	  try {
	    fserial.createNewFile();
	    fOutSerial = new FileWriter(fserial);
	    nextSerialNumber = BigInteger.ONE;
	    serialNbString = nextSerialNumber.toString();
	    fOutSerial.write(serialNbString, 0, serialNbString.length());
	    fOutSerial.close();
	  }
	  catch (Exception e) {
	    throw new FileNotFoundException("Unable to create serial number file: "
					    + fserial.getPath());
	  }
	}
      }
      FileReader fInSerial = new FileReader(fserial);
      char cbuf[] = new char[200];

      synchronized(_lock) {
	int byteRead = fInSerial.read(cbuf);
	fInSerial.close();
	serialNbString = new String(cbuf, 0, byteRead);
	if (log.isDebugEnabled()) {
	  log.debug("Serial = " + serialNbString);
	}
	nextSerialNumber = new BigInteger(serialNbString);
	// Write next serial number back to file.
	fOutSerial = new FileWriter(fserial);

	// For now, do a simple increment algorithm.
	serialNbString = nextSerialNumber.add(BigInteger.ONE).toString();
	fOutSerial.write(serialNbString, 0, serialNbString.length());
	fOutSerial.close();
      }

      return nextSerialNumber;
    }

  public void publishCertificate(CertificateEntry certEntry) {
    
    caOperations.publishCertificate(certEntry);

  }

  public  void publishCertificate(X509Certificate clientX509,
                                  int type, PrivateKey pk)   {
    
    CertificateEntry certEntry =null;
    CertificateRevocationStatus certStatus = CertificateRevocationStatus.VALID;
    CertificateType certType = null;
    log.debug(" Got type:"+ type);
    log.debug("got DN :"+ clientX509.getSubjectDN().getName());
    try {
      switch (type) {
      case CertificateUtility.CACert:
        certType = CertificateType.CERT_TYPE_CA;
        X509CRL crl=crlCache.createEmptyCrl(clientX509.getSubjectDN().getName(),
                                              pk,caPolicy.CRLalgorithmId.getName());
        String modifiedTime=DateUtil.getCurrentUTC();
        certEntry = new CACertificateEntry(clientX509,certStatus,certType,crl,modifiedTime);
        break;
      default:
        certType = CertificateType.CERT_TYPE_END_ENTITY;
        certEntry = new CertificateEntry(clientX509,certStatus,certType);
      }
    }
    catch (Exception exp) {
      log.warn(" Unable to create CRL for"+ clientX509.getSubjectDN().getName()+
               exp.getMessage());
    }
     
    caOperations.publishCertificate(certEntry);
        
  }

  /** Sign a PKCS10 certificate signing request with a CA key
   */
  public X509CertImpl signX509Certificate(PKCS10 clientRequest)
    throws IOException, CertificateEncodingException, NoSuchAlgorithmException,
    CertificateException, SignatureException, InvalidKeyException,
    NoSuchProviderException
    {
      // Get X500 name of Certificate authority
      //SignerInfo si = null;
      if (caX509cert == null) {
        if (log.isWarnEnabled()) {
          X500Name name = clientRequest.getSubjectName();
          log.warn("Unable to sign certificate of " + name
                   + ". CA does not have a key yet.");
        }
        throw new RuntimeException("X509 certificate of CA is null");
      }
      if (log.isDebugEnabled()) {
        log.debug("CA x509:" + caX509cert.toString());
      }

      // does it have signing capability?
      KeyUsageExtension keyusage = null;
      try {
        String s = OIDMap.getName(new ObjectIdentifier("2.5.29.15"));
        if(s != null) {
          keyusage = (KeyUsageExtension)((X509CertImpl)caX509cert).get(s);
        }
      } catch (Exception ex) {
        if (log.isDebugEnabled())
          log.debug("Exception in getKeyUsage: "
                    + ex.toString());
      }
      if (keyusage == null || keyusage.getBits().length < KeyManagementConstants.KEYUSAGE_CERT_SIGN_BIT
          || !keyusage.getBits()[KeyManagementConstants.KEYUSAGE_CERT_SIGN_BIT])
        throw new CertificateException("Certificate is not authorized to sign.");


      //if (log.isDebugEnabled()) {
      //log.debug("x500: " + caX500IssuerName.getCommonName());
      //}

      // Get Signature object for certificate authority
      List caPrivateKeyList = keyRing.findPrivateKey(caX500Name);
      if (caPrivateKeyList == null || caPrivateKeyList.size() == 0) {
        log.warn("Unable to sign certificate request. CA does not have a private key");
        return null;
      }
      PrivateKey caPrivateKey = ((PrivateKeyCert)caPrivateKeyList.get(0)).getPrivateKey();
      //Signature caSignature = Signature.getInstance(caPrivateKey.getAlgorithm());
      // TODO
      //Signature caSignature = Signature.getInstance("SHA1withRSA");
      // caSignature.initSign(caPrivateKey);

      //X500Signer caX500signer = new X500Signer(caSignature, caX500Name);

      /**
       * Client certificate attributes
       * Valid attributes:
       *  version, serialNumber, algorithmID, issuer, validity, subject, key
       *  issuerID, subjectID, extensions
       */
      X509CertImpl clientCertificate = (X509CertImpl)setX509CertificateFields(clientRequest);

      // Set subject unique ID
      /*
        CertificateSubjectUniqueIdentity certSubjectUniqueIdentity = new CertificateSubjectUniqueIdentity();
        clientCertInfo.set("subjectuniqueid", certSubjectUniqueIdentity);
      */


      // Sign certificate
      clientCertificate.sign(caPrivateKey, caPolicy.algorithmId.getName());
      if (log.isDebugEnabled()) {
        log.debug("Signed certificate: " + clientCertificate.toString());
      }

      return clientCertificate;
    }

  /** Read a file with Base64 encoded certificates, which are each bounded at
   * the beginning by -----BEGIN CERTIFICATE-----, and bounded at the end by
   * -----END CERTIFICATE-----.
   * We convert the FileInputStream (which does not support mark and reset)
   * to a ByteArrayInputStream (which supports those methods), so that each
   * call to generateCertificate consumes only one certificate, and the read
   * position of the input stream is positioned to the next certificate in the file.
   */
  public ArrayList readX509Certificates(String filename)
    throws FileNotFoundException, CertificateException, IOException
    {
      FileInputStream fis = new FileInputStream(filename);
      DataInputStream dis = new DataInputStream(fis);

      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      byte[] bytes = new byte[dis.available()];
      dis.readFully(bytes);
      ArrayList certs = new ArrayList();
      ByteArrayInputStream bais = new ByteArrayInputStream(bytes);

      while (bais.available() > 0) {
        Certificate cert = cf.generateCertificate(bais);
        certs.add(cert);
        if (log.isDebugEnabled()) {
          log.debug(cert.toString());
        }
      }
      return certs;
    }

  /** Parse a PKCS#7-formatted certificate reply stored in a file and
   * extracts all the certificates from it.
   */
  public ArrayList parsePkcs7Certificate(String filename)
    throws FileNotFoundException, CertificateException, IOException
    {
      FileInputStream fis = new FileInputStream(filename);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      Collection c = cf.generateCertificates(fis);
      Iterator i = c.iterator();
      ArrayList certs = new ArrayList();
      while (i.hasNext()) {
        Certificate cert = (Certificate)i.next();
        certs.add(cert);
        if (log.isDebugEnabled()) {
          log.debug(cert.toString());
        }
      }
      return certs;
    }

  private byte[] getTotalBytes(InputStream inputstream)
    throws IOException
    {
      byte abyte0[] = new byte[8192];
      ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream(2048);
      bytearrayoutputstream.reset();
      int i;
      while((i = inputstream.read(abyte0, 0, abyte0.length)) != -1)
        bytearrayoutputstream.write(abyte0, 0, i);
      return bytearrayoutputstream.toByteArray();
    }

  
	
  public X509Certificate setX509CertificateFields(PKCS10 clientRequest)
    throws IOException, CertificateException
    {

      /* Retrieve attributes from the PKCS10 request */
      PKCS10Attributes attr = clientRequest.getAttributes();
      if (log.isDebugEnabled()) {
        log.debug("setX509CertificateFields. PKCS10 attributes:"
                  +clientRequest );
        log.debug(attr.toString());
        if(caPolicy==null) {
          log.debug("in setX509CertificateFields. ca Policy is null");
        }
      }

      /**
       * Client certificate attributes
       * Valid attributes:
       *  version, serialNumber, algorithmID, issuer, validity, subject, key
       *  issuerID, subjectID, extensions
       */
      X509CertInfo clientCertInfo = new X509CertInfo();

      // Set certificate parameters

      // Set version number
      CertificateVersion certversion = new CertificateVersion(caPolicy.certVersion);
      clientCertInfo.set("version", certversion);

      // Set serial number
      BigInteger nextSerialNumber = getNextSerialNumber();
      CertificateSerialNumber certSerialNumber = new CertificateSerialNumber(nextSerialNumber);
      clientCertInfo.set("serialNumber", certSerialNumber);

      // Set algorithm ID
      CertificateAlgorithmId certAlgorithmId =
        new CertificateAlgorithmId(caPolicy.algorithmId);
      clientCertInfo.set("algorithmID", certAlgorithmId);

      // Set issuer
      CertificateIssuerName certIssuerName = new CertificateIssuerName(caX500Name);
      if (log.isDebugEnabled()) {
        log.debug("Certificate issuer is " + caX500Name.toString());
      }
      clientCertInfo.set("issuer", certIssuerName);

      // Set validity
      // Certificate can be used right away
      // move back 1 hour for time difference
      Date curdate = new Date();
      long dtime = curdate.getTime() - caPolicy.timeEnvelope * 1000L;
      Date date_notbefore = new Date(dtime);

      // Certificate is valid for a number of days
      dtime = curdate.getTime() + caPolicy.howLong * 1000L;
      Date date_notafter = new Date(dtime);

      if (log.isDebugEnabled()) {
        log.debug("Certificate validity is " + date_notbefore + " to " + date_notafter);
        log.debug("Current time: " + curdate + " and howLong: " + caPolicy.howLong);
      }

      CertificateValidity certValidity = new CertificateValidity(date_notbefore, date_notafter);
      clientCertInfo.set("validity", certValidity);

      // check if the title field is set, the field specifies the certificate type
      // if the certificate is generated by user using keytool, the field will not be set
      // also check the accuracy of the field
      X500Name clientReqName = clientRequest.getSubjectName();
      String dname = clientReqName.getName();
      String title = CertificateUtility.findAttribute(dname, "t");
      if (log.isDebugEnabled())
        log.debug("=====> Title from client request: " + title);

      if (title == null) {
        if (log.isDebugEnabled()) {
          log.debug("setCertificateFields: receive a request without title: " + dname);
          log.debug("Setting title as user.");
        }
        dname += ",t=" + CertificateCacheConstants.CERT_TITLE_USER;
        title = CertificateCacheConstants.CERT_TITLE_USER;
      }

      X500Name clientX500Name = new X500Name(dname);

      // Set subject name
      CertificateSubjectName certSubjectName = new CertificateSubjectName(clientX500Name);
      clientCertInfo.set("subject", certSubjectName);

      // Set client certificate
      CertificateX509Key clientCertificateX509Key =
        new CertificateX509Key(clientRequest.getSubjectPublicKeyInfo());

      // Set key
      clientCertInfo.set("key", clientCertificateX509Key);

      // Set extensions

      X509CertImpl clientCertificate = new X509CertImpl(clientCertInfo);

      if (caPolicy.certVersion >= 2) {
        String s = OIDMap.getName(new ObjectIdentifier("2.5.29.15"));
        //log.debug("=====> ObjectIdentifier: " + s);

        KeyUsageExtension keyusage = new KeyUsageExtension();
        boolean isSigner = false;
        if (title.equals(CertificateCacheConstants.CERT_TITLE_CA))
          isSigner = true;
        else {
          keyusage.set("digital_signature", new Boolean(true));
          keyusage.set("key_encipherment", new Boolean(true));
          keyusage.set("data_encipherment", new Boolean(true));

          // Set keyusage
          if (title.equals(CertificateCacheConstants.CERT_TITLE_NODE)) {
            // need signing capability?
            // only for node with key signing ability defined in CA crypto policy
            if (caPolicy.nodeIsSigner)
              isSigner = true;
          }
        }
        if (isSigner)
          keyusage.set("key_certsign", new Boolean(true));
        if(s != null) {
          clientCertificate.set(s, keyusage);
        }
      }

      return clientCertificate;
    }

  public void createCertificateRevocationList()
    {
    }

  public int  revokeCertificate(String caDN ,String userUniqueIdentifier)
    throws IOException, Exception, CertificateException
    {
      int status=1;
      CertificateEntry userCertEntry=caOperations.findCertByIdentifier(userUniqueIdentifier);
      CACertificateEntry caCertEntry=null;
      List list=caOperations.findCertByDistinguishedName(caDN);
      if(list.size()>1) {
        String msg = "Unable to revoke.Multiple CA CertificateEntry f dor CA DN :" +caDN;
        log.warn(msg);
        throw new IOException(msg);
      }
      Iterator iter=list.iterator();
      caCertEntry=(CACertificateEntry)iter.next();
      if(userCertEntry==null) {
        String msg = "Unable to revoke. Could not find CertificateEntry for userUniqueIdentifier  :" +userUniqueIdentifier;
        log.warn(msg);
        throw new IOException(msg);
      }
      if(caCertEntry==null) {
        String msg = "Unable to revoke. Could not find CACertificateEntry for CA DN   :" +caDN;
        log.warn(msg);
        throw new IOException(msg);
      }
      if(caCertEntry instanceof CACertificateEntry) {
     
        X500Name x500name=new X500Name(caDN);
        List caprivatekeyList = keyRing.findPrivateKey(x500name);
        PrivateKey caprivatekey = ((PrivateKeyCert)caprivatekeyList.get(0)).getPrivateKey();
        if(caprivatekey==null) {
          String msg = "Unable to revoke. Could not find PrivateKey for CA :" + caDN;
          log.warn(msg);
          throw new IOException(msg);
        }
        try {
          if(log.isDebugEnabled()) {
            log.debug("Found private key going to revoke certificate in caOperations :");
          }
          CertificateRevocationStatus userstatus=userCertEntry.getCertificateRevocationStatus();
          if(userstatus.equals(CertificateRevocationStatus.REVOKED)) {
            status=-2;
            return status;
          }
          X509Certificate caCert= caCertEntry.getCertificate();
          X509Certificate userCert=userCertEntry.getCertificate();
          PublicKey capublickey=caCert.getPublicKey();
          Certificate [] certchain=keyRing.buildCertificateChain(userCert);
          boolean validchain=false;
          if((certchain!=null)&&(certchain.length>0)) {
            PublicKey certpk=null;
            for(int i=0;i<certchain.length;i++) {
              certpk=((X509Certificate)certchain[i]).getPublicKey();
              if(!certpk.equals(capublickey)){
                continue;
              }
              else {
                validchain=true;
                break;
              }
            }
        
          }
          if(validchain) {
            X509Certificate issuercertificate = null;
            issuercertificate = CertificateUtility.getX509Certificate(certchain[1]);
            X509CRL newCrl=null;
            X509CRL oldCrl=caCertEntry.getCRL();
            newCrl= crlCache.createCRL(caCert,oldCrl,userCert,issuercertificate, caprivatekey,
                                         caPolicy.CRLalgorithmId.getName());
            caCertEntry.setCRL(newCrl);
            caOperations.publishCertificate(caCertEntry);
            keyRing.publishCertificate(caCertEntry);
            userCertEntry.setCertificateRevocationStatus(CertificateRevocationStatus.REVOKED);
            caOperations.publishCertificate(userCertEntry);
            
          }
          else {
            String msg = "CA with DN name  : "
              + caCert.getSubjectDN().getName()
              +" cannot revoke user certificate with dn name : "
              + userCert.getSubjectDN().getName() + ". Chain is not valid. ";
            log.warn(msg);
            throw new CertificateException(msg);
          }
        
        }
        catch (Exception exp) {
          String msg = "Unable to revoke key. uniqueIdentifier : " +userUniqueIdentifier 
            + ". Reason:" + exp;
          log.warn(msg, exp);
          throw exp;
        }
      }
      else {
        throw new Exception("Not a CACertificateEntry:");
      }
      return status;
    }

  public int  revokeAgentCertificate(String caDN ,String agentName)
    throws IOException, Exception, CertificateException
    {
      //String filter = "(cn=" + agentName + ")";
      if (log.isDebugEnabled()){
        log.debug(" revokeAgentCertificate called for ca dn :"+ caDN + "agent Name : "+agentName);
      }
      return _revokeCertificate(caDN, agentName);
    }

  
  private int _revokeCertificate(String caDN, String agentName)
    throws IOException,Exception,CertificateException    {
     if (log.isDebugEnabled()){
        log.debug(" _revokeCertificate called for ca dn :"+ caDN + "agent Name : "+agentName);
      }
    int status=1;
    CACertificateEntry caCertEntry=null;
    List list=caOperations.findCertByDistinguishedName(caDN);
    if(list.size()>1) {
      String msg = "Unable to revoke.Multiple CA CertificateEntry f dor CA DN :" +caDN;
      log.warn(msg);
      throw new IOException(msg);
    }
    Iterator iter=list.iterator();
    caCertEntry=(CACertificateEntry)iter.next();
    if(caCertEntry==null) {
      String msg = "Unable to revoke. Could not find CACertificateEntry for CA DN   :" +caDN;
      log.warn(msg);
      throw new IOException(msg);
    }
    
    PrivateKey caprivatekey =null;
    if(caCertEntry instanceof CACertificateEntry) {
      X500Name x500name=new X500Name(caDN);
      List caprivatekeyList = keyRing.findPrivateKey(x500name);
      caprivatekey = ((PrivateKeyCert)caprivatekeyList.get(0)).getPrivateKey();
      if(caprivatekey==null) {
        String msg = "Unable to revoke. Could not find PrivateKey for CA :" + caDN;
        log.warn(msg);
        throw new IOException(msg);
      }
    }
    else {
      throw new Exception("Not a CACertificateEntry:");
    }
    List certlist=caOperations.findCertByCN(agentName);
    if(list.isEmpty()) {
      String msg = "Unable to revoke. Could not find certificates for agent :" +agentName ;
      log.warn(msg);
      throw new IOException(msg);
    }
    Iterator certiterator=certlist.iterator();
    CertificateEntry userCertEntry=null;
    boolean modified =false;
    while(certiterator.hasNext()) {
      userCertEntry=(CertificateEntry)certiterator.next();
      try {
        if(log.isDebugEnabled()) {
          log.debug("Found private key going to revoke certificate in _revokeAgentCertificate :");
        }
        CertificateRevocationStatus userstatus=userCertEntry.getCertificateRevocationStatus();
        if(userstatus.equals(CertificateRevocationStatus.REVOKED)) {
          status=-2;
          return status;
        }
        X509Certificate caCert= caCertEntry.getCertificate();
        X509Certificate userCert=userCertEntry.getCertificate();
        PublicKey capublickey=caCert.getPublicKey();
        Certificate [] certchain=keyRing.buildCertificateChain(userCert);
        boolean validchain=false;
        if((certchain!=null)&&(certchain.length>0)) {
          PublicKey certpk=null;
          for(int i=0;i<certchain.length;i++) {
            certpk=((X509Certificate)certchain[i]).getPublicKey();
            if(!certpk.equals(capublickey)){
              continue;
            }
            else {
              validchain=true;
              break;
            }
          }
        }
        if(validchain) {
          X509Certificate issuercertificate = null;
          issuercertificate = CertificateUtility.getX509Certificate(certchain[1]);
          X509CRL newCrl=null;
          X509CRL oldCrl=caCertEntry.getCRL();
          newCrl= crlCache.createCRL(caCert,oldCrl,userCert,issuercertificate, caprivatekey,
                                       caPolicy.CRLalgorithmId.getName());
          caCertEntry.setCRL(newCrl);
          userCertEntry.setCertificateRevocationStatus(CertificateRevocationStatus.REVOKED);
          caOperations.publishCertificate(userCertEntry);
          modified=true;
          
        }
        else {
          if(modified) {
            publishModifiedCRL(caCertEntry);
          }
          String msg = "CA with DN name  : "
            + caCert.getSubjectDN().getName()
            +" cannot revoke user certificate with dn name : "
            + userCert.getSubjectDN().getName() + ". Chain is not valid. ";
          log.warn(msg);
          throw new CertificateException(msg);
        }
        
      }
      catch (Exception exp) {
        /* if an exception occours already modified crl list should be published 
         */
        if(modified) {
          publishModifiedCRL(caCertEntry);
        }
        String msg = "Unable to revoke key for agent : " + agentName
          + ". Reason:" + exp;
        log.warn(msg, exp);
        throw exp;
        
      }
    }
    if(modified) {
      publishModifiedCRL(caCertEntry);
    }
    return status;
  }

  private void publishModifiedCRL(CACertificateEntry caCertEntry)throws Exception  {
    caOperations.publishCertificate(caCertEntry);
    keyRing.publishCertificate(caCertEntry);
    
  }
 
}
