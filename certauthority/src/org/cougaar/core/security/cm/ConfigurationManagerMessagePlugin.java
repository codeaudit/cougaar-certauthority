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
 



package org.cougaar.core.security.cm;


import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.cm.message.VerifyAgentAddRequest;
import org.cougaar.core.security.cm.message.VerifyResponse;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;


/**
 * Listens For Messages from other Entities.  For now , the society
 * configuration is on the blackboard
 *
 * @author ttschampel
 * @version $Revision: 1.1 $
 */
public class ConfigurationManagerMessagePlugin extends ComponentPlugin {
  private static final String PLUGIN_NAME = "ConfigurationManagerMessagePlugin";
  private static UnaryPredicate relayPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        return o instanceof SharedDataRelay
        && ((SharedDataRelay) o).getContent() instanceof CMMessage;
      }
    };

  private IncrementalSubscription relaySubscription;
  private LoggingService logging;

  /**
   * Set logging service
   *
   * @param service Logging Service
   */
  public void setLoggingService(LoggingService service) {
    this.logging = service;
  }


  /**
   * Setup subscriptions
   */
  public void setupSubscriptions() {
    relaySubscription = (IncrementalSubscription) getBlackboardService()
                                                    .subscribe(relayPredicate);
  }


  /**
   * Execute subscriptions
   */
  public void execute() {
    handleVerifyRequests();
  }


  /**
   *
   */
  private void handleVerifyRequests() {
    Iterator i = relaySubscription.getAddedCollection().iterator();
    while (i.hasNext()) {
      SharedDataRelay relay = (SharedDataRelay) i.next();
      if (logging.isDebugEnabled()) {
        logging.debug(ConfigurationManagerMessagePlugin.PLUGIN_NAME
          + " Added Relay " + relay);
      }

      CMMessage cmMessage = (CMMessage) relay.getContent();
      if (cmMessage.getRequest() instanceof VerifyAgentAddRequest) {
        processVerifyAddAgentRequest(relay, cmMessage);
      }
    }
  }


  private void processVerifyAddAgentRequest(SharedDataRelay relay,
    CMMessage cmMessage) {
    VerifyResponse response = null;
    VerifyAgentAddRequest request = (VerifyAgentAddRequest) cmMessage
      .getRequest();
    String agent = request.getAgent();
    String node = request.getAddToNode();
    if (logging.isDebugEnabled()) {
      logging.debug(PLUGIN_NAME + " received add verify for " + agent
        + " to node" + node);
    }

    SocietyConfiguration sc = getSocietyConfiguration();
    if (sc != null) {
      HashMap agents = sc.getAgentConfigurations();
      Object object = agents.get(agent);
      boolean valid = false;
      if (object != null) {
        AgentConfiguration config = (AgentConfiguration) object;
        String agentType = config.getAgentType();
        if(logging.isDebugEnabled()){
        	logging.debug("Checking that " + node + " has facet role of " + agentType);
        	
        }
        HashMap nodeMap = sc.getNodeConfigurations();
        Object nodeObj = nodeMap.get(node);
        if(nodeObj!=null){
        	NodeConfiguration nc = (NodeConfiguration)nodeObj;
        	String nodeType  = 	nc.getNodeType();
        	if(logging.isDebugEnabled()){
        		logging.debug("Node role is " + nodeType + " and needed type is " + agentType);
        		
        	}
        	if(nodeType.equals(agentType)){
        		valid=true;
        	}
        }
        
      }else{
      	//if node configuration does not exist both are
      	//low security so allow it
      	HashMap nodeMap = sc.getNodeConfigurations();
      	Object nodeObj = nodeMap.get(node);
      	if(nodeObj==null){
      		valid = true;
      	}
      }

      response = new VerifyResponse(valid);
      cmMessage.setResponse(response);
    } else {
      if (logging.isWarnEnabled()) {
        logging.warn("Society configuration not found");
      }

      response = new VerifyResponse(false);
      cmMessage.setResponse(response);
    }


    relay.updateResponse(relay.getSource(), cmMessage);
    getBlackboardService().publishChange(relay);
  }


  private SocietyConfiguration getSocietyConfiguration() {
    SocietyConfiguration sc = null;
    Collection coll = getBlackboardService().query(new UnaryPredicate() {
          public boolean execute(Object o) {
            return o instanceof SocietyConfiguration;
          }
        });

    Iterator iter = coll.iterator();
    int index = 0;
    while (iter.hasNext()) {
      sc = (SocietyConfiguration) iter.next();
      index++;
    }

    if (index > 1) {
      if (logging.isWarnEnabled()) {
        logging.warn("More than 1 society configuration found!");
      }
    }

    return sc;
  }
}
