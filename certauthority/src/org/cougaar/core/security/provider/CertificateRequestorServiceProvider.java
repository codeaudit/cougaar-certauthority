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


import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertificateRequestor;

/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.1 $
 * @author $author$
 */
public class CertificateRequestorServiceProvider extends 
  BaseSecurityServiceProvider {
  private static CertificateRequestor certRequestor = null;

  /**
   * Constructor
   *
   * @param sb The service broker for the service.
   */
  public CertificateRequestorServiceProvider(ServiceBroker sb, String mySecurityCommunity) {
  	super(sb, mySecurityCommunity);
  }

  protected synchronized Service getInternalService(ServiceBroker sb, 
	    Object requestor, 
	    Class serviceClass) {
// Implemented as a singleton service
  	if (certRequestor == null) {
      certRequestor = new CertificateRequestor(sb);
  	}
  	return certRequestor;
  }

  protected void releaseInternalService(ServiceBroker sb,
			Object requestor,
			Class serviceClass,
			Object service) {
  }
}
