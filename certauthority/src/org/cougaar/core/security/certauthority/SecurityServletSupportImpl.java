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

import javax.servlet.Servlet;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.service.BlackboardQueryService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.servlet.SimpleServletSupportImpl;

public class SecurityServletSupportImpl
  extends SimpleServletSupportImpl
  implements SecurityServletSupport
{
  private SecurityPropertiesService securityPropertiesService;
  //private CertificateManagementService certificateManagementService;
  private ServiceBroker serviceBroker;
  //private NamingService ns;
  
  public SecurityServletSupportImpl(String path,
				    MessageAddress agentId,
				    BlackboardQueryService blackboard,
				    ServiceBroker sb,
				    LoggingService log) {
    super(path, agentId, blackboard, log);
    //super(path, agentId, blackboard, ns, log);
    serviceBroker = sb;
  }

  public SecurityPropertiesService getSecurityProperties(Servlet servlet) {
    // Get the security properties service
    securityPropertiesService = (SecurityPropertiesService)
      serviceBroker.getService(
	servlet,
	SecurityPropertiesService.class,
	null);
    if (securityPropertiesService == null) {
      throw new RuntimeException(
	"Unable to obtain security properties service");
    }
    return securityPropertiesService;
  }

  public ServiceBroker getServiceBroker() {
    return serviceBroker;
  }
}
