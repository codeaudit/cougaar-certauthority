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

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.NodeConfiguration;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class PendingCertCache
  extends Hashtable
{
  private CaPolicy caPolicy = null;            // the policy of the CA
  private NodeConfiguration nodeConfiguration;
  private String caDN;

  private static PendingCertCache thisCache = null;
  private CertificateManagementService signer = null;
  private ServiceBroker serviceBroker;
  private ConfigParserService configParser = null;
  private LoggingService log;

  // singleton
  // only started once
  public synchronized static PendingCertCache getPendingCache(
    String cadnname, ServiceBroker sb) {
    if (thisCache == null) {
      try {
        thisCache = new PendingCertCache(cadnname, sb);
      }
      catch (Exception e) {
	Logger logger =
	  LoggerFactory.getInstance().createLogger("PendingCertCache");
	if (logger == null) {
	  throw new RuntimeException("Unable to get LoggingService");
	}
        logger.error("Error creating PendingCertCache: "
		     + e.toString());
      }
    }
    return thisCache;
  }

  private PendingCertCache(final String cadnname, ServiceBroker sb) 
    throws Exception {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this, LoggingService.class, null);
    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
        configParser = (ConfigParserService)
           serviceBroker.getService(this, ConfigParserService.class, null);
      signer = (CertificateManagementService)
	serviceBroker.getService(new CertificateManagementServiceClientImpl(cadnname),
				 CertificateManagementService.class, null);
        return null;
    }
    });
    try {
      caPolicy = configParser.getCaPolicy(cadnname);
    }
    catch (Exception e) {
      throw new Exception("Unable to read policy for DN="
			  + cadnname + " - " + e );
    }
    init();
  }

  private void init()
    throws Exception {
    caDN = caPolicy.caDnName.getName();

    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
        nodeConfiguration = new NodeConfiguration(caDN, serviceBroker);
        return null;
      }
    });
    
    if (log.isDebugEnabled()) {
      log.debug("PendingCertCache: Top level directory is :"
			 + nodeConfiguration.getNodeDirectory());
    }
    loadRequests();
  }


  private synchronized void loadRequests()
    throws Exception {
    // there are 3 directories storing certificates which should be loaded
    // 1. the pending request, which will be used when viewing and approving requests
    put(nodeConfiguration.getPendingDirectoryName(caDN),
	loadCertCache(nodeConfiguration.getPendingDirectoryName(caDN)));

    // 2. the valid certificate, which will be used when need to reply client with
    //  a certificate approved
    put(nodeConfiguration.getX509DirectoryName(caDN),
	loadCertCache(nodeConfiguration.getX509DirectoryName(caDN)));

    // 3. the denied request, which will be checked when client send a query request
    //  to check whether the request has been processed
    put(nodeConfiguration.getDeniedDirectoryName(caDN),
	loadCertCache(nodeConfiguration.getDeniedDirectoryName(caDN)));
  }

  private Hashtable loadCertCache(String certsubdir) {
    Hashtable certtable = new Hashtable();
    ArrayList filelist = getCertFileList(certsubdir);
    for (int i = 0; i < filelist.size(); i++) {
      ArrayList certs = getCertFromFileList(certsubdir, (String)filelist.get(i));
      for (int j = 0; j < certs.size(); j++) {
        certtable.put(filelist.get(i), certs.get(j));
      }
    }
    return certtable;
  }

  public Certificate getCertificate(String whichstate, String alias) {
    Hashtable certtable = (Hashtable)get(whichstate);
    if (certtable == null)
      return null;
    return (Certificate)certtable.get(alias);
  }

  // using public key as key
  public Certificate getCertificate(String whichstate, PublicKey publicKey) {
    if (log.isDebugEnabled()) {
      log.debug("looking up key in " + whichstate);
    }
    Hashtable certtable = (Hashtable)get(whichstate);
    if (certtable == null)
      return null;

    //String pubkeyValue = new String(publicKey.getEncoded());
    if (log.isDebugEnabled()) {
      log.debug("getting cert with pub key: ");
    }
    if (log.isDebugEnabled())
    log.debug("Looking public key:\n" + publicKey.toString());

    for (Enumeration en = certtable.elements(); en.hasMoreElements(); ) {
      Certificate certimpl = (Certificate)en.nextElement();
      if (log.isDebugEnabled()) {
	log.debug("Certificate in hash map:\n"
		  + certimpl.getPublicKey().toString() );
      }
      if (publicKey.equals(certimpl.getPublicKey())) {
	if (log.isDebugEnabled()) {
	 log.debug("Found a match");
       }
       return certimpl;
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("Found no match");
    }
    return null;
  }

  public static void addCertificateToList(String whichstate, String alias, Certificate cert) {
    // NOTE: if the cache is not loaded yet, no need to put the cert in cache
    // the time that the cache is loaded the new cert will be loaded
    // this operation is to keep the cache in sych in case the cache exists
    if (thisCache != null) {
      Hashtable certtable = (Hashtable)thisCache.get(whichstate);
      if (certtable != null)
        certtable.put(alias, cert);
    }
  }

  public void moveCertificate(String fromstate, String tostate, String alias) {
    Certificate certimpl = getCertificate(fromstate, alias);
    if (certimpl != null) {
      addCertificateToList(tostate, alias, certimpl);

      Hashtable certtable = (Hashtable)thisCache.get(fromstate);
      if (certtable != null)
        certtable.remove(alias);

      // from is always pending, so just add it
      String frompath = fromstate + File.separatorChar + alias + ".cer";
      String topath = tostate + File.separatorChar + alias + ".cer";

      File fromfile = new File(frompath);
      if (fromfile.exists())
        fromfile.renameTo(new File(topath));
      if (log.isDebugEnabled()) {
        log.debug("moving file: " + fromfile + " to: " + topath);
      }
    }
  }

  // Richard - get list of certificate request from the files saved
  public ArrayList getCertFileList(String certdir) {
    ArrayList ar = new ArrayList();
    File f = new File(certdir);
    if (log.isDebugEnabled()) {
      log.debug("Looking up certificates in " + certdir);
    }
    if (f.exists()) {
      File [] certfiles = f.listFiles();
      for (int i = 0; i < certfiles.length; i++) {
        File certfile = certfiles[i];
        String filename = certfile.getName();
        int separatorIndex = filename.lastIndexOf(".cer");
        if (separatorIndex > 0) {
          // extract the alias from filename
          ar.add(filename.substring(0, separatorIndex));
        }

      }
    }
    if (log.isDebugEnabled()) {
      log.debug("Found " + ar.size() + " certificates in " + certdir);
    }
    return ar;
  }

  public ArrayList getCertFromFileList(String certsubdir, String alias) {
    ArrayList certlist = new ArrayList();
    File certfile = new File(certsubdir + File.separatorChar + alias + ".cer");
    try {
      //X509CertImpl ClientX509 = new X509CertImpl(new FileInputStream(certfile));
      certlist = signer.readX509Certificates(certfile.getPath());
    }
    catch(CertificateException certificateexception) {
      if (log.isInfoEnabled()) {
	log.info("Certificate Exception: " + certificateexception);
      }
    }
    catch(IOException ioexception1) {
      if (log.isInfoEnabled()) {
	log.info("IO exception: " + ioexception1);
      }
    }
    catch(Exception e) {
      log.error("Exception when loading certificate from file: "
		+ certfile.getPath(), e);
    }
    return certlist;
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
