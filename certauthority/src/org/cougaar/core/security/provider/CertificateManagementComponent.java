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


package org.cougaar.core.security.provider;

import java.util.List;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.node.NodeControlService;
import org.cougaar.core.security.services.crypto.CertificateRequestorService;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;

public final class CertificateManagementComponent
  extends SecurityComponent
{
  protected BindingSite bindingSite = null;
  private LoggingService log;
  private String mySecurityCommunity;
  private ServiceBroker serviceBroker;
  private ServiceBroker rootServiceBroker;
  private CryptoPolicyService cps;
  private CertificateManagementServiceProvider certMgrSP;
  private CertificateRequestorServiceProvider crsp;

  public CertificateManagementComponent() {
  }

  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List argument to setParameter");
    }
    List l = (List) o;
    if (l.size() != 1) {
      throw new IllegalArgumentException(this.getClass().getName()
					 + " should take 1 parameter, got " + l.size()
					 + ". Fix configuration file");
    }
    else {
      mySecurityCommunity = l.get(0).toString();
    }
  }

  private void setLoggingService() {
    if (log == null) {
      ServiceBroker sb = bindingSite.getServiceBroker();
      log = (LoggingService)
	sb.getService(this,
		      LoggingService.class, null);
    }
  }

  public void setBindingSite(BindingSite bs) {
    bindingSite = bs;
  }

  public void load() {
    super.load();
    setLoggingService();
    serviceBroker = bindingSite.getServiceBroker();

    if (log.isDebugEnabled()) {
      log.debug("loading Certificate ManagementComponent");
    }

    // Get root service broker
    NodeControlService nodeControlService = (NodeControlService)
      serviceBroker.getService(this, NodeControlService.class, null);
    if (nodeControlService != null) {
      rootServiceBroker = nodeControlService.getRootServiceBroker();
      if (rootServiceBroker == null) {
        throw new RuntimeException("Unable to get root service broker");
      }
      serviceBroker.releaseService(this, NodeControlService.class, nodeControlService);
    }
    else {
      // We are running outside a Cougaar node.
      // No Cougaar services are available.
      rootServiceBroker = serviceBroker;
    }

    cps = (CryptoPolicyService)
      serviceBroker.getService(this, CryptoPolicyService.class, null);
    if (cps == null) {
      addServiceAvailableListener();
    }
    else {
      registerServices();
    }
  }

  private void addServiceAvailableListener() {
    serviceBroker.addServiceListener(new ServiceAvailableListener() {
      public void serviceAvailable(ServiceAvailableEvent ae) {
        Class sc = ae.getService();
        if (sc == CryptoPolicyService.class && cps == null) {
          cps = (CryptoPolicyService)
            serviceBroker.getService(this, CryptoPolicyService.class, null);
          if (cps != null) {
            registerServices();
          }
        }
      }
    });
  }

  private void registerServices() {
    certMgrSP = new CertificateManagementServiceProvider(serviceBroker, mySecurityCommunity);
    rootServiceBroker.addService(CertificateManagementService.class, certMgrSP);
    if (log.isDebugEnabled()) {
    	log.debug("CertificateManagementService started");
    }
    crsp = new CertificateRequestorServiceProvider(serviceBroker, mySecurityCommunity);
    rootServiceBroker.addService(CertificateRequestorService.class, crsp);
    if (log.isDebugEnabled()) {
    	log.debug("CertificateRequestorService started");
    }
    
  }

  public void setState(Object loadState) {}
  public Object getState() {return null;}

  public synchronized void stop() {
    super.stop();
    // unload services in reverse order of "load()"
    ServiceBroker sb = bindingSite.getServiceBroker();
    
    if (crsp != null) {
      rootServiceBroker.revokeService(CertificateRequestorService.class, crsp);
      crsp = null;
    }
    if (certMgrSP != null) {
      rootServiceBroker.revokeService(CertificateManagementService.class, certMgrSP);
      certMgrSP = null;
    }
    if (cps != null) {
      sb.releaseService(this, CryptoPolicyService.class, cps);
      cps = null;
    }
    
    // release LoggingService
    if (log != null) {
      sb.releaseService(this, LoggingService.class, log);
      log = null;
    }
    serviceBroker = null;
    rootServiceBroker = null;
  }
}
