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


import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.security.cm.service.CMService;
import org.cougaar.core.security.cm.service.CMServiceImpl;


/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.1 $
 * @author $author$
 */
public class CMServiceProvider implements ServiceProvider {
  CMServiceImpl cmImplRef = null;
  String queryFile = null;

  /**
   * Constructor
   *
   * @param sb The service broker for the service.
   */
  public CMServiceProvider(ServiceBroker sb) {
    cmImplRef = new CMServiceImpl(sb);
  }

  /**
   * Returns a reference to CMService
   *
   * @param sb Service broker
   * @param requestor The requestor
   * @param serviceClass The service class
   *
   * @return The Service
   */
  public Object getService(ServiceBroker sb, Object requestor,
    Class serviceClass) {
    if (CMService.class.isAssignableFrom(serviceClass)) {
      if (cmImplRef == null) {
        cmImplRef = new CMServiceImpl(sb);
      } else {
        cmImplRef.setServiceBroker(sb);
      }

      return cmImplRef;
    } else {
      return cmImplRef;
    }
  }


  /**
   * Releases the GUI service
   *
   * @param sb
   * @param requestor The object requesting the service
   * @param serviceClass Class of the requested service
   * @param service The Service
   */
  public void releaseService(ServiceBroker sb, Object requestor,
    Class serviceClass, Object service) {
  }
}
