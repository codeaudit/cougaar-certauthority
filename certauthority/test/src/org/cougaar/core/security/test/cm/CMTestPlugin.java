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



package org.cougaar.core.security.test.cm;


import java.util.Enumeration;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.cm.message.VerifyAgentAddRequest;
import org.cougaar.core.security.cm.message.VerifyResponse;
import org.cougaar.core.security.cm.service.CMService;
import org.cougaar.core.security.provider.CMServiceProvider;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewPrepositionalPhrase;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.util.UnaryPredicate;


/**
 * Plugin to test the CM. Subscribe to tasks published by the CMTestServlet.
 *
 * @author ttschampel
 */
public class CMTestPlugin extends ComponentPlugin {
  /** Logging Service */
  private LoggingService logging;
  /** Subscription to results from CM */
  private IncrementalSubscription subs = null;
  /** CMService */
  private CMService cmService = null;
  /** Predicate for CMResults */
  private UnaryPredicate predicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof SharedDataRelay) {
        SharedDataRelay sd = (SharedDataRelay) o;
        if ((sd.getResponse() != null) && sd.getResponse() instanceof VerifyResponse && (sd.getContent() != null) && sd.getContent() instanceof VerifyAgentAddRequest && ((VerifyAgentAddRequest) sd.getContent()).getAgent().equals(getAgentIdentifier().getAddress())) {
          return true;
        }
      }

      return false;
    }
  };

  /** Subscription to test cm tasks */
  private IncrementalSubscription testSubs = null;
  /** Predicate to test cm tasks */
  private UnaryPredicate testCMPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof Task) {
        Task t = (Task) o;
        if ((t.getVerb() != null) && t.getVerb().toString().equals(CMTestServlet.CM_TEST_VERB)) {
          return true;
        }
      }

      return false;
    }
  };

  /**
   * Set LoggingService
   *
   * @param service
   */
  public void setLoggingService(LoggingService service) {
    this.logging = service;
  }


  /**
   * load plugin
   */
  public void load() {
    super.load();

    cmService = (CMService) this.getServiceBroker().getService(this, CMService.class, null);
    if (cmService == null) {
      this.getServiceBroker().addService(CMService.class, new CMServiceProvider(getServiceBroker()));
      cmService = (CMService) this.getServiceBroker().getService(this, CMService.class, null);

    }
  }


  /**
   * Set up subscriptions
   */
  public void setupSubscriptions() {
    this.subs = (IncrementalSubscription) this.getBlackboardService().subscribe(predicate);
    this.testSubs = (IncrementalSubscription) this.getBlackboardService().subscribe(this.testCMPredicate);

  }


  /**
   * process subscriptions
   */
  public void execute() {
    Enumeration testEnumeration = testSubs.getAddedList();
    while (testEnumeration.hasMoreElements()) {
      Task task = (Task) testEnumeration.nextElement();
      String moveToNode = (String) task.getPrepositionalPhrase(CMTestServlet.DEST_NODE_PREP).getIndirectObject();
      VerifyAgentAddRequest request = new VerifyAgentAddRequest(moveToNode, this.getAgentIdentifier().getAddress());
      cmService.sendMessage(request, getBlackboardService());
    }

    Enumeration enumeration = subs.getChangedList();
    while (enumeration.hasMoreElements()) {
      SharedDataRelay relay = (SharedDataRelay) enumeration.nextElement();
      VerifyResponse response = (VerifyResponse) relay.getResponse();
      if (logging.isInfoEnabled()) {
        logging.info("CM Response:" + response.getValidRequest());
      }
      DomainService ds = (DomainService)this.getServiceBroker().getService(this,DomainService.class, null);
      PlanningFactory pf = (PlanningFactory)ds.getFactory("planning");
      
      NewTask resultTask = pf.newTask();
      NewPrepositionalPhrase npp = pf.newPrepositionalPhrase();
      npp.setPreposition(CMTestServlet.SUCCESS_PHRASE);
      npp.setIndirectObject(new Boolean(response.getValidRequest()));
      resultTask.addPrepositionalPhrase(npp);
      resultTask.setVerb(Verb.getVerb(CMTestServlet.CM_TEST_VERB_RESPONSE));
      getBlackboardService().publishAdd(resultTask);
    }
  }
}
