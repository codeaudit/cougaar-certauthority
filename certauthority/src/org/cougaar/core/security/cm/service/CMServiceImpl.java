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
 



package org.cougaar.core.security.cm.service;


import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.cm.CMMessage;
import org.cougaar.core.security.cm.CMMessage.CMRequest;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.util.UID;


/**
 * Configuration Manager Service Implementation     For now use property to get
 * cm agent :     <b>(org.cougaar.core.security.cm.location)</b>
 *
 * @author ttschampel
 * @version $Revision: 1.1 $
 */
public class CMServiceImpl implements CMService {
  /** Logging Service */
  private LoggingService logging;
  /** Service Broker */
  private ServiceBroker serviceBroker;
  /** UIDService */
  private UIDService uidService;
  /** Agent Identification Service */
  private AgentIdentificationService agentIdService;
  /** Location of Configuration Manager */
  String cmAgentLocation = null;
  private MessageAddress defaultAddress = MessageAddress.getMessageAddress("RootCaManager");
  /**
   * Creates a new CMService object.
   *
   * @param sb Service Broker used to get Cougaar Services
   */
  public CMServiceImpl(ServiceBroker sb) {
    serviceBroker = sb;
    load();
  }

  /**
   * Set the service broker
   *
   * @param sb ServiceBroker
   */
  public void setServiceBroker(ServiceBroker sb) {
    this.serviceBroker = sb;
  }


  /**
   * Load service
   */
  private void load() {
    logging = (LoggingService) serviceBroker.getService(this,
        LoggingService.class, null);


    uidService = (UIDService) serviceBroker.getService(this, UIDService.class,
        null);
    agentIdService = (AgentIdentificationService) serviceBroker.getService(this,
        AgentIdentificationService.class, null);
    cmAgentLocation = System.getProperty(
        "org.cougaar.core.security.cm.location");
    if (cmAgentLocation == null) {
      //use current agent as location
      //cmAgentLocation = agentIdService.getMessageAddress().getAddress();
      cmAgentLocation = this.defaultAddress.getAddress();
    }

    if (logging.isDebugEnabled()) {
      logging.debug("Configuration Manager location parameter is null");
    }
  }


  /**
   * Send a message to the configuration manager.  This should be called within
   * a BlackboardService Transaction.
   *
   * @param request CMRequest to send
   * @param bbs DOCUMENT ME!
   */
  public void sendMessage(CMRequest request, BlackboardService bbs) {
    //create shared data relay and publish to blackboard
    MessageAddress target = MessageAddress.getMessageAddress(cmAgentLocation);

    if (logging.isDebugEnabled()) {
      logging.debug("Sending CMRequest to " + target);
    }

    UID uid = uidService.nextUID();
    CMMessage content = new CMMessage();
    content.setRequest(request);
    Object response = null;
    MessageAddress source = agentIdService.getMessageAddress();
    SharedDataRelay relay = new SharedDataRelay(uid, source, target, content,
        response);
    bbs.publishAdd(relay);

  }
}
