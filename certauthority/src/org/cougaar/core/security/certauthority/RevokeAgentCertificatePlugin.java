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


import java.util.ArrayList;
import java.util.Enumeration;
import java.util.TimerTask;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.constants.BlackboardCompromise;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.util.UnaryPredicate;


/**
 * Revoke and agents certificate. Subscribes to relay
 *
 * @author ttschampel
 */
public class RevokeAgentCertificatePlugin extends ComponentPlugin {
  /** Plugin name */
  private static final String pluginName = "RevokeAgentCerficatePlugin";
  /** Subscription to relay */
  private IncrementalSubscription relaySubs = null;
  /** Predicate for relay */
  private UnaryPredicate relayPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof SharedDataRelay) {
        SharedDataRelay sdr = (SharedDataRelay) o;
        if ((sdr.getContent() != null) && sdr.getContent() instanceof Task) {
          Task t = (Task) sdr.getContent();
          return (t.getVerb() != null) && t.getVerb().toString().equals(BlackboardCompromise.REVOKE_AGENT_CERT_VERB);
        }
      }

      return false;
    }
  };

  /** Logging Service */
  private LoggingService logging = null;

  /**
   * Set Logging Service
   *
   * @param s LoggingService
   */
  public void setLoggingService(LoggingService s) {
    this.logging = s;
  }


  /**
   * Setup subscriptions
   */
  protected void setupSubscriptions() {
    this.relaySubs = (IncrementalSubscription) getBlackboardService().subscribe(this.relayPredicate);

  }


  /**
   * Process subscriptions
   */
  protected void execute() {
    if (logging.isDebugEnabled()) {
      logging.debug(pluginName + " executing");
    }

    checkForNewTasks();
  }


  /**
   * Check if there are new revoke agent tasks
   */
  private void checkForNewTasks() {
    Enumeration enumeration = this.relaySubs.getAddedList();
    while (enumeration.hasMoreElements()) {
      SharedDataRelay sdr = (SharedDataRelay) enumeration.nextElement();
      Task task = (Task) sdr.getContent();
      if (logging.isDebugEnabled()) {
        logging.debug("Got mesage to revoke agent:" + task);
      }

      //get caDNs
      ArrayList caDNs = (ArrayList) task.getPrepositionalPhrase(BlackboardCompromise.CA_DN_PREP).getIndirectObject();

      //get agent name
      String agentName = (String) task.getPrepositionalPhrase(BlackboardCompromise.FOR_AGENT_PREP).getIndirectObject();
      if (caDNs == null) {
        if (logging.isErrorEnabled()) {
          logging.error("Recevied revoke agent request without a CADN");
        }
      } else {
        for (int i = 0; i < caDNs.size(); i++) {
          String caDN = (String) caDNs.get(i);
          if (logging.isDebugEnabled()) {
            logging.debug("Revoke agent cert for " + agentName + " and caDN:" + caDN);
          }

          try {
            CertificateManagementService keymanagement = (CertificateManagementService) this.getServiceBroker().getService(new CertificateManagementServiceClientImpl(caDN), CertificateManagementService.class, null);
            if (keymanagement == null) {
              if (logging.isDebugEnabled()) {
                logging.debug("CertificateManagementService  is null");
              }
            }
            
            //keymanagement.revokeAgentCertificate(caDN, agentName);
            RevokeTask revokeTask = new RevokeTask(caDN, agentName, keymanagement);
            ThreadService threadService = (ThreadService)this.getServiceBroker().getService(this, ThreadService.class, null);
            Schedulable sch = threadService.getThread(this, revokeTask);
            sch.schedule(1);
            sch.start();
         
          } catch (Exception e) {
            if (logging.isErrorEnabled()) {
              logging.error("Error has occured due to  following reason", e);
            }
          }
        }
      }

      sdr.updateResponse(sdr.getSource(), task);
      getBlackboardService().publishChange(sdr);
    }
  }

  private class CertificateManagementServiceClientImpl implements CertificateManagementServiceClient {
    private String caDN;

    public CertificateManagementServiceClientImpl(String aCaDN) {
      caDN = aCaDN;
    }

    public String getCaDN() {
      return caDN;
    }
  }
  
  private class RevokeTask extends TimerTask{
  	String caDn = null;
  	String agentName = null;
  	CertificateManagementService keymanagement  = null;
  	 public RevokeTask(String caDn,  String agentName, CertificateManagementService keymanagement){
  	 	this.caDn = caDn;
  	 	this.agentName = agentName;	
  	 	this.keymanagement = keymanagement;
  	 }
  	  public void run(){
  	  			if(logging.isDebugEnabled()){
  	  				logging.debug("Revoking agent cert:" + agentName);
  	  			}
  	  			try{
					keymanagement.revokeAgentCertificate(caDn, agentName);
  	  			}catch(Exception e){
  	  				if(logging.isErrorEnabled()){
  	  					logging.error("Error revoking agent cert",e);
  	  				}
  	  			}
  	  	
  	  }
  }
}
