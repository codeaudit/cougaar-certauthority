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



package org.cougaar.core.security.crypto;


import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.SocketException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignedObject;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.security.PrivilegedAction;
import java.security.AccessController;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.naming.CACertificateEntry;
import org.cougaar.core.security.policy.CertificateAttributesPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.crypto.CRLCacheService;
import org.cougaar.core.security.services.crypto.CertificateRequestorService;
import org.cougaar.core.security.util.DateUtil;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.service.LoggingService;

import sun.misc.BASE64Encoder;
import sun.security.pkcs.PKCS10;
import sun.security.x509.X500Name;
import sun.security.x509.X500Signer;
import sun.security.x509.X509CertImpl;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision: 1.4 $
 */
public class CertificateRequestor implements CertificateRequestorService {
  private ServiceBroker serviceBroker;
  private ConfigParserService configParser;
  private CryptoClientPolicy cryptoClientPolicy;
  private CertificateCacheService cacheservice;
  private KeyRingService keyRing;
  private LoggingService log;
  private String role;

  // parameter for polling CA when it is busy handling all the requests
  // how long interval to wait for polling CA 
  private int _waittime = 10000;
  // repeat polling CA how many times 
  private int _waitrepeat = 6;
  // start warning after how long
  private long _pollThreshold = 180000;
  // time when poll threshold starts to count
  private long _pollStart;

  /**
   * Creates a new CertificateRequestor object.
   *
   * @param sb DOCUMENT ME!
   * @param configparser DOCUMENT ME!
   * @param irole DOCUMENT ME!
   */
  public CertificateRequestor(ServiceBroker sb) {
    serviceBroker = sb;

    cacheservice = (CertificateCacheService) serviceBroker
      .getService(this, CertificateCacheService.class, null);
    keyRing = (KeyRingService) serviceBroker.getService(this,
            KeyRingService.class, null);
    configParser = (ConfigParserService)serviceBroker.getService(this,
				 ConfigParserService.class,
				 null);
    if (configParser == null) {
    	throw new RuntimeException("unable to get config parser service");
    }
    SecurityPolicy[] sp = configParser.getSecurityPolicies(CryptoClientPolicy.class);
    cryptoClientPolicy = (CryptoClientPolicy) sp[0];
    log = (LoggingService) serviceBroker.getService(this, LoggingService.class,
        null);
    if (log.isDebugEnabled()) {
      log.debug("Certificate Requestor started.");
    }

    SecurityPropertiesService secprop = (SecurityPropertiesService)serviceBroker.getService(this,
			  SecurityPropertiesService.class,
			  null);
    if (secprop != null) {
    	role =secprop.getProperty(SecurityPropertiesService.SECURITY_ROLE);
    }
    if (role == null) {
      if (log.isInfoEnabled()) {
        log.info("Role is not defined. Setting empty role");
      }
      role = "";
    }
      try {
        String waitPoll = System.getProperty("org.cougaar.core.security.configpoll", "5000");
        _waittime = Integer.parseInt(waitPoll);

        waitPoll = System.getProperty("org.cougaar.core.security.waitrepeat", "6");
        _waitrepeat = Integer.parseInt(waitPoll);

        waitPoll = System.getProperty("org.cougaar.core.security.pollThreshold", "180000");
        _pollThreshold = Integer.parseInt(waitPoll);
      } catch (Exception ex) {
        if (log.isWarnEnabled()) {
          log.warn("Unable to parse configpoll property: " + ex.toString());
        }
      }

      _pollStart = System.currentTimeMillis();
  }

  /**
   * Add a key pair to the key ring. If needed, a new key pair is generated and
   * stored in the keystore. If the key being generated is for the node, the a
   * PKCS#10 request is sent to the Certificate Authority. If the CA replies
   * by signing the node's certificate, the certificate is installed in the
   * keystore. If the key being generated is an agent key, then the node acts
   * as a CA for the agent: the node signs the agent's certificate and also
   * sends the certificate to the node's CA. If necessary, a node's key is
   * recursively created for the node. If the keyAlias parameter is null, then
   * it is assumed that no key exists yet in the keystore. In that case, a new
   * key is generated. If alias is not null, an existing key is used. In that
   * case, we first lookup the LDAP directory. The CA may have already signed
   * and published the certificate, in which case it is not necessary to
   * re-generated and send a PKCS#10 request to the CA.
   *
   * @param dname - the common name of the entity (agent or node)
   * @param keyAlias - the alias of the key in the keystore
   * @param isCACert DOCUMENT ME!
   * @param trustedCaPolicy DOCUMENT ME!
   *
   * @return - the private key of the entity
   */
  public synchronized PrivateKey addKeyPair(X500Name dname, String keyAlias,
    boolean isCACert, TrustedCaPolicy trustedCaPolicy) {
    String request = "";
    String reply = "";

    if (cacheservice == null) {
      if(log.isWarnEnabled()){
        log.warn("Unable to get Certificate Cache in  addKeyPair");
      }
    }

    //is node?
    String nodeName = NodeInfo.getNodeName();
    String commonName = null;
    if (cacheservice != null) {
      commonName = cacheservice.getCommonName(dname);
    }

    if (log.isDebugEnabled()) {
      log.debug("Creating key pair for " + dname + " - Node name:" + nodeName
        + " - Common Name=" + commonName);
    }

    if (nodeName == null) {
      if (log.isErrorEnabled()) {
        log.error("Cannot get node name");
      }

      return null;
    }

    String alias = null;
    PrivateKey privatekey = null;
    /**
     * Handle CA cert
     */
    if (isCACert) {
      return addCAKeyPair(dname, keyAlias);
    } else if (cryptoClientPolicy.isCertificateAuthority()) {
      return addKeyPairOnCA(dname, keyAlias);
    }

    try {
      /* If the requested key is for the node, the key is self signed.
       * If the requested key is for an agent, and the node is a signer,
       *  then the agent key is signed by the node.
       * If the node is not a signer, the requested key is self-signed.
       */
      String title = CertificateUtility.findAttribute(dname.getName(), "t");
      CertificateAttributesPolicy certAttribPolicy = cryptoClientPolicy
        .getCertificateAttributesPolicy(trustedCaPolicy);
      X500Name nodex500name = CertificateUtility.getX500Name(CertificateUtility
          .getX500DN(nodeName, title, certAttribPolicy));


      if (commonName.equals(nodeName) /* || commonName.equals(NodeInfo.getHostName())*/
        || ((title != null) && title.equals(CertificateCacheConstants.CERT_TITLE_USER))
        || !certAttribPolicy.nodeIsSigner) {
        // Create a self-signed key and send it to the CA.
        if (keyAlias != null) {
          // Do not create key. There is already one in the keystore.
          alias = keyAlias;
          if (log.isDebugEnabled()) {
            log.debug("Using existing key: " + keyAlias);
          }


          // First, go to the CA to see if the CA has already signed the key.
          // In that case, there is no need to send a PKCS10 request.
          return getNodeCert(nodex500name, trustedCaPolicy);
        } else {
          if (log.isDebugEnabled()) {
            log.debug("Creating key pair for node: " + nodeName);
          }

          alias = makeKeyPair(dname, false, certAttribPolicy);
        }


        // At this point, the key pair has been added to the keystore,
        // but we don't have the reply from the certificate authority yet.
        // Send the public key to the Certificate Authority (PKCS10)
        if (!cryptoClientPolicy.isCertificateAuthority()) {
          X509Certificate cert = null;
          if (cacheservice != null) {
            cert = cacheservice.getCertificate(alias);
          }

          if (log.isDebugEnabled()) {
            log.debug("*  * * * *Generating reqular cert request");
          }

          if ((title != null)
            && title.equals(CertificateCacheConstants.CERT_TITLE_AGENT)) {
            String[] requestResult = this
              .generateSigningCertificateRequestForAgent(cert, alias);
            request = requestResult[0];
            String nodeSign = requestResult[1];
            if (log.isDebugEnabled()) {
              log.debug("Sending PKCS10 Request to CA for Agent");
            }

            // Sign PKCS10 request with node key and send agent cert to CA
            reply = this.sendPKCS(commonName, request, nodeSign, "PKCS10", trustedCaPolicy, nodeName);
          } else {
            request = generateSigningCertificateRequest(cert, alias);
            if (log.isDebugEnabled()) {
              log.debug("Sending PKCS10 request to CA");
            }

            reply = sendPKCS(request, "PKCS10", trustedCaPolicy);
          }
        } else {
          if (log.isDebugEnabled()) {
            log.debug("Is Cert Authority");
          }
        }
      } else {
        PrivateKey nodeprivatekey = null;
        try {
          nodeprivatekey = getNodeCert(nodex500name, trustedCaPolicy);
        } catch (Exception nex) {
          if (log.isWarnEnabled()) {
            log.warn("Failed to get node cert. Reason: " + nex);
          }
        }

        if (nodeprivatekey == null) {
          if (commonName.equals(NodeInfo.getHostName())) {
            if (log.isDebugEnabled()) {
              log.debug("Creating self signed host key");
            }

            makeKeyPair(dname, false, certAttribPolicy);
          }

          return null;
        }

        // The Node key should exist now
        if (log.isDebugEnabled()) {
          log.debug("Searching node key again: " + nodeName);
        }

        List nodex509List = null;
        if (keyRing != null) {
          nodex509List = keyRing.findCert(nodex500name,
              KeyRingService.LOOKUP_KEYSTORE, true);
        }        

        X509Certificate nodex509 = null;
        if (nodex509List.size() > 0) {
          nodex509 = ((CertificateStatus) nodex509List.get(0)).getCertificate();
        }

        if (log.isDebugEnabled()) {
          log.debug("Node key is: " + nodex509);
        }

        if (nodex509 == null) {
          // There was a problem during the generation of the node's key.
          // Stop the procedure.
          if (log.isErrorEnabled()) {
            log.error("Unable to get node's key");
          }

          return null;
        }

        if (keyAlias != null) {
          // Do not create key. There is already one in the keystore.
          alias = keyAlias;
          if (log.isDebugEnabled()) {
            log.debug("Using existing key: " + keyAlias);
          }
        } else {
          if (log.isDebugEnabled()) {
            log.debug("Creating key pair for agent: " + dname);
          }

          alias = makeKeyPair(dname, false, certAttribPolicy);
        }


        // Generate a pkcs10 request, then sign it with node's key
        //String nodeAlias = findAlias(nodeName);
        X509Certificate cert = null;
        if (cacheservice != null) {
          cert = cacheservice.getCertificate(alias);
        }

        if (log.isDebugEnabled()) {
          log.debug(
            "* * * * * * * * * *  Generating a signing certificate request for other...");
        }

        request = this.generateSigningCertificateRequest(cert, alias);

        // Sign PKCS10 request with node key and send agent cert to CA
        reply = this.signPKCS(request, nodex509.getSubjectDN().getName(),
            trustedCaPolicy);
      }
    } catch (Exception e) {
      if (log.isErrorEnabled()) {
        log.error("Unable to create key in addKeyPair: " + dname + " - Reason:",
          e);
      }
    }

    if (alias != null) {
      privatekey = processPkcs7Reply(alias, reply);
    }

    return privatekey;
  }


  private PrivateKey addKeyPairOnCA(X500Name dname, String keyAlias) {
    String alias = null;
    PrivateKey privatekey = null;
    if (log.isDebugEnabled()) {
      log.debug("Creating cert on CA: " + dname.toString() + " : " + keyAlias);
    }

    if (cacheservice == null) {
      if (log.isWarnEnabled()) {
        log.warn("Unable to get Certificate Cache service in addKeyPairOn");
      }
    }

    try {
      X500Name[] caDNs = configParser.getCaDNs();
      CertificateAttributesPolicy certAttribPolicy = cryptoClientPolicy
        .getCertificateAttributesPolicy();
      if (caDNs.length == 0) {
        if (log.isDebugEnabled()) {
          log.debug(
            "No CA key created yet, the certificate can not be created.");
        }

        return null;
      }

      String caDN = configParser.getCaDNs()[0].getName();

      // is the CA key valid
      if (!cryptoClientPolicy.isRootCA()) {
        List certList = null;
        if (keyRing != null) {
          certList = keyRing.getValidCertificates(configParser.getCaDNs()[0]);
        }

        if ((certList == null) || (certList.size() == 0)) {
          if (log.isDebugEnabled()) {
            log.debug(
              "CA key created but is not approved by upper level CA yet.");
          }

          String caCommonName = null;
          if (cacheservice != null) {
            caCommonName = cacheservice.getCommonName(configParser.getCaDNs()[0]);
          }

          String caAlias = keyRing.findAlias(caCommonName);
          if (log.isDebugEnabled()) {
            log.debug("CA alias: " + caAlias);
          }

          addCAKeyPair(configParser.getCaDNs()[0], caAlias);
          return null;
        }
      }

      if (keyAlias != null) {
        alias = keyAlias;
      } else {
        alias = makeKeyPair(dname, false, certAttribPolicy);
      }

      // sign it locally
      CertificateManagementService km = (CertificateManagementService) serviceBroker
        .getService(new CertificateManagementServiceClientImpl(caDN),
          CertificateManagementService.class, null);
      if (log.isDebugEnabled()) {
        log.debug("Signing certificate locally with " + caDN);
      }

      X509Certificate cert = null;
      if (cacheservice != null) {
        cert = cacheservice.getCertificate(alias);
      }

      X509CertImpl certImpl = km.signX509Certificate(generatePKCS10Request(
            cert, alias));

      if (cacheservice != null) {
        privatekey = cacheservice.getKey(alias);
      }

      // publish certificate to LDAP
      km.publishCertificate(certImpl, CertificateUtility.EntityCert, privatekey);

      // install
      keyRing.installCertificate(alias, new X509Certificate[] { certImpl });
    } catch (Exception e) {
      if (log.isDebugEnabled()) {
        log.warn("Unable to create key: " + dname + " - Reason:", e);
      }
    }

    return privatekey;
  }


  private PrivateKey addCAKeyPair(X500Name dname, String keyAlias) {
    String alias = null;
    PrivateKey privatekey = null;
    
    if (cacheservice == null) {
      if (log.isWarnEnabled()) {
        log.warn("Unable to get Certificate Cache service in addCAKeyPair");
      }
    }

    if (!cryptoClientPolicy.isCertificateAuthority()) {
      if (log.isErrorEnabled()) {
        log.error("Cannot make CA cert, this node is not a CA");
      }
      return null;
    } else {
      try {
        CertificateAttributesPolicy certAttribPolicy = cryptoClientPolicy
          .getCertificateAttributesPolicy();

        // this must be a subordinate CA
        if (keyAlias != null) {
          alias = keyAlias;
          // lookup upper level CA's LDAP
          if (log.isDebugEnabled()) {
            log.debug("CA key already created, check upper level CA LDAP");
          }

          /*
             No need tp parse dn as Search should be able to do this and publish the certificate to certCache
                   //String filter = "(cn=" + dname.getCommonName() + ")";
                   String filter =CertificateUtility. parseDN(dname.getName());
                   // there should be only one upper level CA, for now
           */
          X500Name x500signer = new X500Name(cryptoClientPolicy.getIssuerPolicy()[0].caDN);
          keyRing.findCert(x500signer);

          /*
             Commented from original code
             CertDirectoryServiceClient certFinder =
             getCACertDirServiceClient(cryptoClientPolicy.getIssuerPolicy()[0].caDN);
             lookupCertInLDAP(filter, certFinder);
           */
          X509Certificate certificate = null;
          if (cacheservice != null) {
            certificate = cacheservice.getCertificate(alias);
          }

          if (certificate != null) {
            // look it up from keystore, if found in LDAP should have installed it
            List keyList = null;
            if (keyRing != null) {
              keyList = keyRing.getValidPrivateKeys(dname);
            }

            if ((keyList != null) && (keyList.size() != 0)) {
              privatekey = ((PrivateKeyCert) keyList.get(0)).getPrivateKey();
            }

            if (privatekey != null) {
              CertificateStatus cs = ((PrivateKeyCert) keyList.get(0))
                .getCertificateStatus();
              X509Certificate[] certForImport = null;
              if (keyRing != null) {
                certForImport = keyRing.establishCertChain(certificate,
                    cs.getCertificate());
              }

              if (cacheservice != null) {
                cacheservice.setKeyEntry(alias, privatekey, certForImport);
                cacheservice.saveCertificateInTrustedKeyStore((X509Certificate) cacheservice
                  .getCertificate(alias), alias);
              }

              //return privatekey;
            }
          }

          // else send the request again
        } else {
          alias = makeKeyPair(dname, true, certAttribPolicy);
        }

        if (privatekey == null) {
          // does it need to be submitted to somewhere else to handle?
          if (cryptoClientPolicy.isRootCA()) {
            if (log.isDebugEnabled()) {
              log.debug("creating root CA.");
            }

            if (cacheservice != null) {
              // Save the certificate in the trusted CA keystore
              cacheservice.saveCertificateInTrustedKeyStore((X509Certificate) cacheservice
                .getCertificate(alias), alias);
              privatekey = cacheservice.getKey(alias);
            }
          }
          // else submit to upper level CA
          else {
            String request = generateSigningCertificateRequest((X509Certificate) cacheservice
                .getCertificate(alias), alias);
            if (log.isDebugEnabled()) {
              log.debug("Sending PKCS10 request to root CA to sign this CA.");
            }

            TrustedCaPolicy[] tc = cryptoClientPolicy.getIssuerPolicy();
            String reply = sendPKCS(request, "PKCS10", tc[0]);
            privatekey = processPkcs7Reply(alias, reply);
            if (privatekey != null) {
              if (cacheservice != null) {
                cacheservice.saveCertificateInTrustedKeyStore((X509Certificate) cacheservice
                  .getCertificate(alias), alias);
              }
            }
          }
        }

        if (privatekey != null) {
          CertificateManagementService km = (CertificateManagementService) serviceBroker
            .getService(new CertificateManagementServiceClientImpl(
                dname.toString()), CertificateManagementService.class, null);
          CRLCacheService crlCache = (CRLCacheService) serviceBroker.getService(this,
          		CRLCacheService.class, null);
          X509CRL crl = crlCache.createEmptyCrl(dname.toString(), privatekey,
              cryptoClientPolicy.getCertificateAttributesPolicy().sigAlgName);
          serviceBroker.releaseService(crlCache,
          		CRLCacheService.class, null);
          String modifiedtime = DateUtil.getCurrentUTC();
          CACertificateEntry caCertEntry = new CACertificateEntry((X509Certificate) cacheservice
              .getCertificate(alias), CertificateRevocationStatus.VALID,
              CertificateType.CERT_TYPE_CA, crl, modifiedtime);
          km.publishCertificate(caCertEntry);

        }
      } catch (Exception e) {
        if (log.isWarnEnabled()) {
          log.warn("Unable to create key: " + dname, e);
        }
      }

      return privatekey;
    }
  }


  /**
   * Generate a PKCS10 request from a public key
   *
   * @param certificate DOCUMENT ME!
   * @param signerAlias DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   *
   * @throws IOException DOCUMENT ME!
   * @throws SignatureException DOCUMENT ME!
   * @throws NoSuchAlgorithmException DOCUMENT ME!
   * @throws InvalidKeyException DOCUMENT ME!
   * @throws KeyStoreException DOCUMENT ME!
   * @throws UnrecoverableKeyException DOCUMENT ME!
   */
  public String generateSigningCertificateRequest(X509Certificate certificate,
    String signerAlias)
    throws IOException, SignatureException, NoSuchAlgorithmException, 
      InvalidKeyException, KeyStoreException, UnrecoverableKeyException {
    PKCS10 request = generatePKCS10Request(certificate, signerAlias);
    String reply = CertificateUtility.base64encode(request.getEncoded(),
        CertificateUtility.PKCS10HEADER, CertificateUtility.PKCS10TRAILER);

    /*
       if (debug) {
       log.debug("GenerateSigningCertificateRequest:\n" + reply);
       }
     */
    return reply;
  }

  Boolean _pkcsLock = new Boolean(true);
  private String sendPKCS(String commonName, String request, String nodeSignature, String pkcs,
    TrustedCaPolicy trustedCaPolicy, String nodeName) {
    String reply = "";

    if (log.isDebugEnabled()) {
      log.debug("Sending request to " + trustedCaPolicy.caURL + ", DN= "
        + trustedCaPolicy.caDN);
    }

    if (trustedCaPolicy == null) {
      if (log.isErrorEnabled()) {
        log.error("No TrustedCaPolicy, cannot send PKCS!");
      }

      return reply;
    }

synchronized (_pkcsLock) {
  for (int i = 0; i < _waitrepeat; i++ ) {
    try {
      URL url = new URL(trustedCaPolicy.caURL);
      HttpURLConnection huc = (HttpURLConnection) url.openConnection();

      // Don't follow redirects automatically.
      huc.setInstanceFollowRedirects(false);
      // Let the system know that we want to do output
      huc.setDoOutput(true);
      // Let the system know that we want to do input
      huc.setDoInput(true);
      // No caching, we want the real thing
      huc.setUseCaches(false);
      // Specify the content type
      huc.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      huc.setRequestMethod("POST");
      PrintWriter out = new PrintWriter(huc.getOutputStream());
      String content = "pkcs=" + URLEncoder.encode(pkcs, "UTF-8");
      content = content + "&role=" + URLEncoder.encode(role, "UTF-8");
      content = content + "&dnname="
        + URLEncoder.encode(trustedCaPolicy.caDN, "UTF-8");
      content = content + "&pkcsdata=" + URLEncoder.encode(request, "UTF-8");
      content = content + "&nodeSignature="
        + URLEncoder.encode(nodeSignature, "UTF-8");
      content = content + "&node=" + URLEncoder.encode(nodeName,"UTF-8");
      out.println(content);
      out.flush();
      out.close();

      BufferedReader in = new BufferedReader(new InputStreamReader(
            huc.getInputStream()));
      StringBuffer sbuf = new StringBuffer();
      int len = 2000; // Size of a read operation
      char[] cbuf = new char[len];
      int read;
      while ((read = in.read(cbuf, 0, len)) > 0) {
        sbuf.append(cbuf, 0, read);
      }

      in.close();
      reply = sbuf.toString();
      reply = URLDecoder.decode(reply, "UTF-8");
      if (log.isDebugEnabled()) {
        log.debug("Reply: " + reply);
      }
      break;
    } catch (Exception e) {
      if (!(e instanceof SocketException)) {
        if (log.isWarnEnabled()) {
          log.warn("Unable to send PKCS request to CA. CA URL:"
                   + trustedCaPolicy.caURL + " . CA DN:" + trustedCaPolicy.caDN
                   + ". CN=" + commonName, e);
        }
        break;
      }
    }

    try {
      Thread.sleep(_waittime);
    } catch (Exception ex) {
      if (log.isDebugEnabled()) {
        log.warn("Thread interruped: ", ex);
      }
    }
  }
}
    if (reply == "") {
      if (System.currentTimeMillis() > _pollStart + _pollThreshold) {
        if (log.isDebugEnabled()) {
          log.warn("Unable to send PKCS request to CA. CA URL:"
                   + trustedCaPolicy.caURL + " . CA DN:" + trustedCaPolicy.caDN
                   + ". CN=" + commonName);
        }                   
      }
    }
    return reply;
  }


  /**
   * DOCUMENT ME!
   *
   * @param certificate DOCUMENT ME!
   * @param signerAlias DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   *
   * @throws IOException DOCUMENT ME!
   * @throws SignatureException DOCUMENT ME!
   * @throws NoSuchAlgorithmException DOCUMENT ME!
   * @throws InvalidKeyException DOCUMENT ME!
   * @throws KeyStoreException DOCUMENT ME!
   * @throws UnrecoverableKeyException DOCUMENT ME!
   */
  public String[] generateSigningCertificateRequestForAgent(
    X509Certificate certificate, String signerAlias)
    throws IOException, SignatureException, NoSuchAlgorithmException, 
      InvalidKeyException, KeyStoreException, UnrecoverableKeyException {
    EncryptionService encryptService = (EncryptionService) serviceBroker
      .getService(this, EncryptionService.class, null);
    PKCS10 request = generatePKCS10Request(certificate, signerAlias);

    String reply = CertificateUtility.base64encode(request.getEncoded(),
        CertificateUtility.PKCS10HEADER, CertificateUtility.PKCS10TRAILER);


    if (log.isDebugEnabled()) {
      log.debug("GenerateSigningCertificateRequestForAgent:\n" + reply);
    }


    //CM stuff
    if (log.isDebugEnabled()) {
      log.debug("Generating message digest and node signature");
    }

    //SHA1withRSA 
    String algorithm = "MD5";
    MessageDigest digest = MessageDigest.getInstance(algorithm);
    digest.update(request.getEncoded());


    String nodeName = NodeInfo.getNodeName();
    if (log.isDebugEnabled()) {
      log.debug("Signing message digest for node: " + nodeName);
    }

    SignedObject signedObj = null;
    algorithm = "SHA1withRSA";
    try {
      signedObj = encryptService.sign(nodeName, algorithm, digest.digest());
    } catch (GeneralSecurityException e) {
      if (log.isWarnEnabled()) {
        log.warn("GeneralSecurityException: " + e);
      }
    } catch (IOException e) {
      if (log.isWarnEnabled()) {
        log.warn("IOException: " + e); 
      }
    }

    ObjectOutputStream out = null;
	ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    try {
      // stream closed in the finally
      out = new ObjectOutputStream(outputStream);
      out.writeObject(signedObj);

    } catch (IOException ex) {
       if(log.isErrorEnabled()){
       	log.error("Could not serialize signed object");
       }
    } finally {
      try {
        if (out != null) {
          out.close();
        }
      } catch (IOException ex) {
        // ignore;
      }
    }
	BASE64Encoder encoder= new BASE64Encoder();
	ByteArrayOutputStream encodeStream = new ByteArrayOutputStream();
	encoder.encodeBuffer(outputStream.toByteArray(), encodeStream);
	String encodeSignedObject = encodeStream.toString("US-ASCII");
    String[] ret = new String[2];
    ret[0] = reply;
    ret[1] = encodeSignedObject;
    return ret;
  }


  /**
   * DOCUMENT ME!
   *
   * @param certificate DOCUMENT ME!
   * @param signerAlias DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   *
   * @throws IOException DOCUMENT ME!
   * @throws SignatureException DOCUMENT ME!
   * @throws NoSuchAlgorithmException DOCUMENT ME!
   * @throws InvalidKeyException DOCUMENT ME!
   * @throws KeyStoreException DOCUMENT ME!
   * @throws UnrecoverableKeyException DOCUMENT ME!
   */
  public PKCS10 generatePKCS10Request(X509Certificate certificate,
    String signerAlias)
    throws IOException, SignatureException, NoSuchAlgorithmException, 
      InvalidKeyException, KeyStoreException, UnrecoverableKeyException {
    PublicKey pk = certificate.getPublicKey();
    PKCS10 request = new PKCS10(pk);
    if (cacheservice == null) {
      log.warn(
        " unabale to get Certificate Cache Service in generatePKCS10Reques");
    }


    // Get Signature object for certificate authority
    PrivateKey signerPrivateKey = null;
    X509Certificate cert = null;
    if (cacheservice != null) {
      signerPrivateKey = cacheservice.getKey(signerAlias);
      cert = cacheservice.getCertificate(signerAlias);
    }


    //Signature signerSignature = Signature.getInstance(signerPrivateKey.getAlgorithm());
    // TODO: find signature algorithm that works with most crypto providers
    Signature signerSignature = Signature.getInstance("SHA1withRSA");
    signerSignature.initSign(signerPrivateKey);

    X500Name signerX500Name = new X500Name(cert.getSubjectDN().toString());
    X500Signer x500signer = new X500Signer(signerSignature, signerX500Name);

    try {
      if (log.isDebugEnabled()) {
        log.debug("Signing certificate request with alias=" + signerAlias);
      }

      request.encodeAndSign(x500signer);
    } catch (CertificateException e) {
      if (log.isErrorEnabled()) {
        log.error("Unable to sign certificate request." + e);
      }
    }

    return request;
  }

  private String sendPKCS(String request, String pkcs,
    TrustedCaPolicy trustedCaPolicy) {
    String reply = "";

    if (log.isDebugEnabled()) {
      log.debug("Sending request to " + trustedCaPolicy.caURL + ", DN= "
        + trustedCaPolicy.caDN);
    }

    if (trustedCaPolicy == null) {
      if (log.isErrorEnabled()) {
        log.error("No TrustedCaPolicy, cannot send PKCS!");
      }
      return reply;
    }

synchronized (_pkcsLock) {
  for (int i = 0; i < _waitrepeat; i++) {
    try {
      URL url = new URL(trustedCaPolicy.caURL);
      HttpURLConnection huc = (HttpURLConnection) url.openConnection();

      // Don't follow redirects automatically.
      huc.setInstanceFollowRedirects(false);
      // Let the system know that we want to do output
      huc.setDoOutput(true);
      // Let the system know that we want to do input
      huc.setDoInput(true);
      // No caching, we want the real thing
      huc.setUseCaches(false);
      // Specify the content type
      huc.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      huc.setRequestMethod("POST");
      PrintWriter out = new PrintWriter(huc.getOutputStream());
      String content = "pkcs=" + URLEncoder.encode(pkcs, "UTF-8");
      content = content + "&role=" + URLEncoder.encode(role, "UTF-8");
      content = content + "&dnname="
        + URLEncoder.encode(trustedCaPolicy.caDN, "UTF-8");
      content = content + "&pkcsdata=" + URLEncoder.encode(request, "UTF-8");
      out.println(content);
      out.flush();
      out.close();

      BufferedReader in = new BufferedReader(new InputStreamReader(
            huc.getInputStream()));
      StringBuffer sbuf = new StringBuffer();
      int len = 2000; // Size of a read operation
      char[] cbuf = new char[len];
      int read;
      while ((read = in.read(cbuf, 0, len)) > 0) {
        sbuf.append(cbuf, 0, read);
      }

      in.close();
      reply = sbuf.toString();
      reply = URLDecoder.decode(reply, "UTF-8");
      if (log.isDebugEnabled()) {
        log.debug("Reply: " + reply);
      }
      break;
    } catch (Exception e) {
      if (!(e instanceof SocketException)) {
        if (log.isDebugEnabled()) {
          log.debug("Unable to send PKCS request to CA. Tried " + i + "/" + _waitrepeat
                    + " times. CA URL:"
                    + trustedCaPolicy.caURL + " . CA DN:" + trustedCaPolicy.caDN, e);
        }
        break;
      }
    }
    try {
      Thread.sleep(_waittime);
    } catch (Exception ex) {
      log.warn("Thread interruped: ", ex);
    }
  }
}
    if (reply == "") {
      if (System.currentTimeMillis() > _pollStart + _pollThreshold) {
        if (log.isWarnEnabled()) { 
          log.warn("Unable to send PKCS request to CA. CA URL:"
                   + trustedCaPolicy.caURL + " . CA DN:" + trustedCaPolicy.caDN);
        }
      }
    }
    return reply;
  }


  private PrivateKey processPkcs7Reply(String alias, String reply) {
    PrivateKey privatekey = null;
    if (cacheservice == null) {
      if (log.isWarnEnabled()) {
        log.warn("Unable to get Certificate cache Service in processPkcs7Reply");
      }
    }

    // Richard -- check whether pending
    String strStat = "status=";
    int statindex = reply.indexOf(strStat);
    if (statindex >= 0) {
      if (log.isDebugEnabled()) {
        log.debug("processPkcs7Reply: certificate in pending mode. ");
      }

      return null;
    }

    if (reply.length() == 0) {
      return null;
    }

    try {
      installPkcs7Reply(alias, new ByteArrayInputStream(reply.getBytes()));
      if (log.isDebugEnabled()) {
        log.debug(" Install Pkcs & reply done ");
      }


      if (cacheservice != null) {
        privatekey = cacheservice.getKey(alias);
      }
    } catch (java.security.cert.CertificateNotYetValidException e) {
      if (log.isWarnEnabled()) {
        Date d = new Date();
        log.warn("Error: Certificate not yet valid for:" + alias + " (" + e
          + ")" + " Current date is " + d.toString());
      }
    } catch (Exception e) {
      if (log.isWarnEnabled()) {
        log.warn("Can't get certificate for " + alias 
                 + ". Reply from CA is:" + reply, e);
        log.warn("Exception caught at ", new Throwable());
      }
    }

    return privatekey;
  }


  /**
   * Install a PKCS7 reply received from a certificate authority
   *
   * @param alias DOCUMENT ME!
   * @param inputstream DOCUMENT ME!
   *
   * @throws CertificateException DOCUMENT ME!
   * @throws KeyStoreException DOCUMENT ME!
   * @throws NoSuchAlgorithmException DOCUMENT ME!
   * @throws UnrecoverableKeyException DOCUMENT ME!
   * @throws IOException DOCUMENT ME!
   */
  public void installPkcs7Reply(String alias, InputStream inputstream)
    throws CertificateException, KeyStoreException, NoSuchAlgorithmException, 
      UnrecoverableKeyException, IOException {
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("installPkcs7Reply"));
    }

    if (log.isDebugEnabled()) {
      log.debug("installPkcs7Reply for " + alias);
    }

    CertificateFactory cf = CertificateFactory.getInstance("X509");
    Collection collection = null;
    try {
      collection = cf.generateCertificates(inputstream);
    } catch (Exception e) {
      if (log.isWarnEnabled()) {
        log.warn("Reply for " + alias + " is not a certificate");
      }
      throw new CertificateException("Reply for " + alias
        + " is not a certificate");
    }

    if (collection.isEmpty()) {
      if (log.isWarnEnabled()) {
        log.warn("Reply for " + alias + " has no certificate");
      }
      throw new CertificateException("Reply has no certificate");
    }

    if (log.isDebugEnabled()) {
      Iterator it = collection.iterator();
      for (int i = 0; it.hasNext(); i++) {
        Object cert = it.next();
        if (log.isDebugEnabled()) {
          log.debug("Reply[" + i + "] - " + cert.getClass().getName());
        }

        if (log.isDebugEnabled()) {
          log.debug(((X509Certificate) cert).toString());
        }
      }
    }

    X509Certificate[] certificateReply = new X509Certificate[0];
    certificateReply = (X509Certificate[]) collection.toArray(certificateReply);

    keyRing.installCertificate(alias, certificateReply);
  }


  /**
   * DOCUMENT ME!
   *
   * @param dname DOCUMENT ME!
   * @param isCACert DOCUMENT ME!
   * @param certAttribPolicy DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   *
   * @throws Exception DOCUMENT ME!
   */
  public String makeKeyPair(X500Name dname, boolean isCACert,
    CertificateAttributesPolicy certAttribPolicy)
    throws Exception {
    if (cacheservice == null) {
      if (log.isWarnEnabled()) {
        log.warn("Unable to get Certificate cache Service in makeKeyPair");
      }
    }

    //generate key pair.
    if (log.isDebugEnabled()) {
      log.debug("makeKeyPair: " + dname);
    }

    String commonName = null;
    if (cacheservice != null) {
      commonName = cacheservice.getCommonName(dname);
    }


    // check whether there is self-signed certificate
    // reuse it
    // if a cert is deny, expired, revoke, etc, status should not be unknown
    if (!isCACert) {
      List certList = null;
      if (cacheservice != null) {
        certList = cacheservice.getCertificates(dname);
      }

      for (int i = 0; (certList != null) && (i < certList.size()); i++) {
        CertificateStatus cs = (CertificateStatus) certList.get(i);
        if ((cs.getCertificateTrust() == CertificateTrust.CERT_TRUST_SELF_SIGNED)
          && (cs.getCertificateType() == CertificateType.CERT_TYPE_END_ENTITY)) {
          String alias = cs.getCertificateAlias();
          if (log.isDebugEnabled()) {
            log.debug("Reusing alias: " + alias);
          }
          return alias;
        }
      }
    }

    String alias = keyRing.getNextAlias(commonName);
    if (log.isDebugEnabled()) {
      log.debug("Make key pair:" + alias + ":" + dname.toString());
    }

    doGenKeyPair(alias, dname, isCACert, certAttribPolicy);
    return alias;
  }


  /**
   * Generate a key pair and a self-signed certificate
   *
   * @param alias DOCUMENT ME!
   * @param dname DOCUMENT ME!
   * @param isCACert DOCUMENT ME!
   * @param certAttribPolicy DOCUMENT ME!
   *
   * @throws Exception DOCUMENT ME!
   */
  public void doGenKeyPair(String alias, X500Name dname, boolean isCACert,
    CertificateAttributesPolicy certAttribPolicy)
    throws Exception {
    String keyAlgName = certAttribPolicy.keyAlgName;
    int keysize = certAttribPolicy.keysize;
    String sigAlgName = certAttribPolicy.sigAlgName;
    long howLong = certAttribPolicy.howLong;

    if (cacheservice == null) {
      if (log.isWarnEnabled()) {
        log.warn("Unable to get Certificate cache Service in doGenKeyPair");
      }
    }

    if (sigAlgName == null) {
      if (keyAlgName.equalsIgnoreCase("DSA")) {
        sigAlgName = "SHA1WithDSA";
      } else if (keyAlgName.equalsIgnoreCase("RSA")) {
        sigAlgName = "MD5WithRSA";
      } else {
        throw new Exception("Cannot derive signature algorithm");
      }
    }

    KeyCertGenerator certandkeygen = new KeyCertGenerator(keyAlgName,
        sigAlgName, null, serviceBroker);
    if (log.isDebugEnabled()) {
      log.debug("Generating " + keysize + " bit " + keyAlgName
        + " key pair and " + "self-signed certificate (" + sigAlgName + ")");
      log.debug("\tfor: " + dname + " - alias:" + alias);
    }

    certandkeygen.generate(keysize);
    PrivateKey privatekey = certandkeygen.getPrivateKey();
    X509Certificate[] ax509certificate = new X509Certificate[1];

    long envelope = certAttribPolicy.regenEnvelope;
    boolean isSigner = false;

    // isCA and is CA DN
    if (isCACert) {
      isSigner = true;
    }
    // is not CA but is node and nodeIsSigner
    else {
      String commonname = null;
      if (cacheservice != null) {
        commonname = cacheservice.getCommonName(dname);
      }

      if (commonname != null) {
        isSigner = commonname.equals(NodeInfo.getNodeName())
          && certAttribPolicy.nodeIsSigner;
      }
    }

    ax509certificate[0] = certandkeygen.getSelfCertificate(dname, envelope,
        howLong, isSigner);
    if (cacheservice != null) {
      cacheservice.setKeyEntry(alias, privatekey, ax509certificate);
    }

    CertificateType certificateType = null;
    CertificateTrust certificateTrust = null;
    if (!isCACert) {
      // Add the certificate to the certificate cache. The key cannot be used
      // yet because it has not been signed by the Certificate Authority.
      certificateType = CertificateType.CERT_TYPE_END_ENTITY;
      certificateTrust = CertificateTrust.CERT_TRUST_SELF_SIGNED;
    } else {
      // This is a certificate authority, so the CA is trusting itself.
      certificateType = CertificateType.CERT_TYPE_CA;
      if (cryptoClientPolicy.isRootCA()) {
        certificateTrust = CertificateTrust.CERT_TRUST_CA_CERT;
      } else {
        certificateTrust = CertificateTrust.CERT_TRUST_SELF_SIGNED;
      }
    }

    CertificateStatus certstatus = new CertificateStatus(ax509certificate[0],
        CertificateOrigin.CERT_ORI_KEYSTORE, CertificateRevocationStatus.VALID,
        certificateType, certificateTrust, alias);
    certstatus.setPKCS10Date(new Date());
    if (log.isDebugEnabled()) {
      log.debug("doGenKeyPair: add Private Key");
    }

    if (cacheservice != null) {
      cacheservice.addCertificate(certstatus);
      cacheservice.addPrivateKey(privatekey, certstatus);
      // Update Common Name to DN hashtable
      cacheservice.addNameToNameMapping(certstatus);
    } else {
      log.warn(
        "Unable to get Certificate cache service in doGenKeyPair..Cannot add certificate to certificate cache");
    }
  }


  /**
   * DOCUMENT ME!
   *
   * @param nodex500name DOCUMENT ME!
   * @param trustedCaPolicy DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   *
   * @throws Exception DOCUMENT ME!
   * @throws CertificateException DOCUMENT ME!
   */
  public PrivateKey getNodeCert(X500Name nodex500name,
    TrustedCaPolicy trustedCaPolicy) throws Exception {
    PrivateKey nodeprivatekey = null;
    X509Certificate nodex509 = null;
    String request = "";
    String reply = "";

    if (cacheservice == null) {
      if (log.isWarnEnabled()) {
        log.warn(" Unable to get Certificate Cache Service in getNodeCert");
      }
    }

    // check if node cert exist
    if (log.isDebugEnabled()) {
      log.debug("Searching node key: " + nodex500name.toString());
    }

    String nodeAlias = null;
    if (cacheservice != null) {
      nodeAlias = cacheservice.findAlias(nodex500name);
    }

    if (nodeAlias != null) {
      List nodex509List = null;
      if (keyRing != null) {
        nodex509List = keyRing.findCert(nodex500name,
            KeyRingService.LOOKUP_KEYSTORE, true);
      }

      if (nodex509List.size() > 0) {
        nodex509 = ((CertificateStatus) nodex509List.get(0)).getCertificate();
      }

      if (nodex509 == null) {
        // maybe approved and in LDAP?
        if (keyRing != null) {
          nodex509List = keyRing.findCert(nodex500name,
              KeyRingService.LOOKUP_LDAP, true);
        }

        if (nodex509List.size() > 0) {
          nodex509 = ((CertificateStatus) nodex509List.get(0)).getCertificate();
        }

        if (nodex509 != null) {
          // install the certificate into keystore
          X509Certificate certificate = null;
          if (cacheservice != null) {
            certificate = cacheservice.getCertificate(nodeAlias);
          }

          if (certificate == null) {
            throw new CertificateException(nodeAlias + "has no certificate.");
          }

          X509Certificate[] certForImport = keyRing.establishCertChain(certificate,
              nodex509);
          if (nodeprivatekey != null) {
            if (cacheservice != null) {
              cacheservice.setKeyEntry(nodeAlias, nodeprivatekey, certForImport);
            }
          }
        }
      }

      if (nodex509 == null) {
        // Richard -- not in LDAP or local keystore
        // might be still pending or denied
        // check with CA, if nothing found then create new key pair
        // if still pending or denied, return null
        if (log.isDebugEnabled()) {
          log.debug("Node certificate not found, checking pending status.");
        }

        X509Certificate cert = null;
        if (cacheservice != null) {
          cert = cacheservice.getCertificate(nodeAlias);
        }

        request = generateSigningCertificateRequest(cert, nodeAlias);
        if (log.isDebugEnabled()) {
          log.debug("Sending PKCS10 request to CA");
        }

        reply = sendPKCS(request, "PKCS10", trustedCaPolicy);
        // check status
        String strStat = "status=";
        int statindex = reply.indexOf(strStat);
        if (statindex >= 0) {
          // in the pending mode
          statindex += strStat.length();
          int status = Integer.parseInt(reply.substring(statindex, statindex
                + 1));
          if (log.isDebugEnabled()) {
            switch (status) {
              case KeyManagementConstants.PENDING_STATUS_PENDING:
                if (log.isDebugEnabled()) {
                  log.debug("Certificate is pending for approval.");
                }

                break;
              case KeyManagementConstants.PENDING_STATUS_DENIED:
                if (log.isDebugEnabled()) {
                  log.debug("Certificate is denied by CA.");
                }

                break;
              case KeyManagementConstants.PENDING_STATUS_APPROVED:
                if (log.isDebugEnabled()) {
                  log.debug("Certificate is approved by CA.");
                }

                break;
              default:
                if (log.isDebugEnabled()) {
                  log.debug("Unknown certificate status:" + status);
                }
            }
          }

          // else approved, why not certificate in the LDAP?
          return null;
        } else {
          // get back the reply right away
          return processPkcs7Reply(nodeAlias, reply);
        }
      }

      if (cacheservice != null) {
        nodeprivatekey = cacheservice.getKey(nodeAlias);
      }
    } else {
      //we don't have a node key pair, so make it
      if (log.isDebugEnabled()) {
        log.debug("Recursively creating key pair for node: " + nodex500name);
      }

      nodeprivatekey = addKeyPair(nodex500name, null, false, trustedCaPolicy);
      if (log.isDebugEnabled()) {
        log.debug("Node key created: " + nodex500name);
      }
    }

    return nodeprivatekey;
  }


  private String signPKCS(String request, String nodeDN,
    TrustedCaPolicy trustedCaPolicy) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      if (log.isDebugEnabled()) {
        log.debug("Signing PKCS10 request with node");
      }

      CertificateManagementService km = (CertificateManagementService) serviceBroker
        .getService(new CertificateManagementServiceClientImpl(nodeDN),
          CertificateManagementService.class, null);
      X509Certificate[] cf = km.processPkcs10Request(new ByteArrayInputStream(
            request.getBytes()));
      PrintStream ps = new PrintStream(baos);
      CertificateUtility.base64EncodeCertificates(ps, cf);
      //get the output to the CA
      String req = baos.toString();
      String reply = sendPKCS(req, "PKCS7", trustedCaPolicy);
    } catch (Exception e) {
      log.warn("Can't get the certificate signed: " + e.getMessage());
    }

    return baos.toString();
  }
  
  /**
   * This function actually is combining the makeKeyPair and getNodeCert
   * functions so that this class can be separated from the core package.
   * @param dname
   * @param makeKey
   * @param certAttribPolicy
   * @return
   * @throws Exception
   */
  public String generateKeyPair(X500Name dname, boolean makeKey, 
  		CertificateAttributesPolicy certAttribPolicy)
  	throws Exception
  {
  	if (!makeKey) {
  		return makeKeyPair(dname, false, certAttribPolicy);
  	}
  	getNodeCert(dname, null);
  	
  	return null;
  }
  

  private class CertificateManagementServiceClientImpl
    implements CertificateManagementServiceClient {
    private String caDN;

    public CertificateManagementServiceClientImpl(String aCaDN) {
      caDN = aCaDN;
    }

    public String getCaDN() {
      return caDN;
    }
  }
}
