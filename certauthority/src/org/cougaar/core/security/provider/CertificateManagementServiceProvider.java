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

import java.util.Hashtable;

import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.certauthority.KeyManagement;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.LoggingService;

public class CertificateManagementServiceProvider 
  extends BaseSecurityServiceProvider
{
  private KeyRingService ksr;
  private Hashtable cmsTable;

  public CertificateManagementServiceProvider(ServiceBroker sb, String community) {
    super(sb, community);
    cmsTable = new Hashtable();
  }

  /**
   * Get a service.
   * @param sb a Service Broker
   * @param requestor the requestor of the service
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @return a service
   */
  protected synchronized Service getInternalService(ServiceBroker sb, 
						    Object requestor, 
						    Class serviceClass) {
    CertificateManagementService cms = null;
    log = (LoggingService) serviceBroker.getService(this, LoggingService.class,
        null);

    if (requestor instanceof CertificateManagementServiceClient) {
      String caDN = ((CertificateManagementServiceClient)requestor).getCaDN();
      if (caDN == null) {
	// A standard node agent having signing authority
	caDN = "";
      }
      cms = (CertificateManagementService)cmsTable.get(caDN);
      if (log.isDebugEnabled()) {
	log.debug("Request CertificateManagementService for " + caDN
	  + " - cms in hashtable: " + cms);
      }
      if (cms == null) {
	try {
	  cms = new KeyManagement(sb);
	  ((KeyManagement)cms).setParameters(caDN);
	  cmsTable.put(caDN, cms);
	}
	catch (Exception e) {
	  cms = null;
	  if (log.isErrorEnabled()) {
	    log.error("Unable to initialize Key Management");
	  }
	}
      }
    }
    else {
      if (log.isErrorEnabled()) {
	log.error("Requestor is not a CertificateManagementServiceClient - Client type:"
		  + requestor.getClass().getName());
      }
      throw new RuntimeException("Requestor is not a CertificateManagementServiceClient:"
				 + requestor.getClass().getName());
    }
    return cms;
  }

  /** Release a service.
   * @param sb a Service Broker.
   * @param requestor the requestor of the service.
   * @param serviceClass a Class, usually an interface, which extends Service.
   * @param service the service to be released.
   */
  protected void releaseInternalService(ServiceBroker sb,
					Object requestor,
					Class serviceClass,
					Object service) {
  }
}
