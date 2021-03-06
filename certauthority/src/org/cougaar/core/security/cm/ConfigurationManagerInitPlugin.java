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

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

/**
 * Creates the SocietyConfiguration representation for time t0. 
 * 	The Society Confiration is constructed from the plugin parameters
 *  passed in to it.  These parameters are generated by the 
 *  configuration_manager.rule which extracts the "role" facet from
 * 	each node and if it has Management role then adds as a plugin
 *  parameters.  If an agent contains the "cm_role" facet then the
 * 	agent is added to the parameters of this plugin.
 * @author ttschampel
 */
public class ConfigurationManagerInitPlugin extends ComponentPlugin {
  //Plugin Constants
  private static final String PLUGIN_NAME = "ConfigurationManagerInitPlugin";
  /** Logging Service */
  private LoggingService logger = null;
  HashMap agentMap = new HashMap();
  HashMap nodeMap = new HashMap();
  /** Society Configuration Value object */
  private SocietyConfiguration societyConfiguration;
  /** Predicate for SocietyConfiguration */
  private UnaryPredicate societyConfigurationPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        return o instanceof SocietyConfiguration;
      }
    };

  /**
   * Setup the Logging Service
   *
   * @param service LoggingService
   */
  public void setLoggingService(LoggingService service) {
    this.logger = service;
  }

  /**
   * Component Load method
   */
  public void load() {
    super.load();
    //get parameters
    Collection parameters = getParameters();
    if (parameters.size() > 0) {
      Iterator iterator = parameters.iterator();

      while (iterator.hasNext()) {
        String parameter = (String) iterator.next();
        String type = parameter.substring(0, parameter.indexOf(","));
        String parameterName = parameter.substring(parameter.indexOf(",") + 1,
            parameter.indexOf("="));
        String parameterType = parameter.substring(parameter.indexOf("=") + 1,
            parameter.length());

        if (type.equals("node")) {
          NodeConfiguration nc = new NodeConfiguration(parameterName,
              parameterType);
          nodeMap.put(parameterName, nc);

        } else if (type.equals("agent")) {
          AgentConfiguration ac = new AgentConfiguration(parameterName,
              parameterType);
          agentMap.put(parameterName, ac);
        }
      }

      societyConfiguration = new SocietyConfiguration(agentMap, nodeMap);
      if(logger.isDebugEnabled()){
      	logger.debug("Configurations:" + societyConfiguration);
      }
    } else {
      if (logger.isErrorEnabled()) {
        logger.error("No Configuration Manager parameters inputted, all agent permitted on all nodes!");
        
      }
      societyConfiguration = new SocietyConfiguration(agentMap, nodeMap);
    }
  }


  /**
   * Setup subscriptions (none) and get t0 society configuration
   */
  public void setupSubscriptions() {
    if (logger.isDebugEnabled()) {
      logger.debug(PLUGIN_NAME + " setupSubscriptions()");
    }

    if (getBlackboardService().didRehydrate()) {
      //get society configuration from blackboard
      if (logger.isDebugEnabled()) {
        logger.debug("Getting Society configuration from blackboard");

      }

      Collection coll = getBlackboardService().query(societyConfigurationPredicate);
      Iterator iter = coll.iterator();
      int index = 0;
      while (iter.hasNext()) {
        index++;
        this.societyConfiguration = (SocietyConfiguration) iter.next();
      }

      if (index == 0) {
        if (logger.isErrorEnabled()) {
          logger.error("No SocietyConfiguration on the blackboard!");
        }
      }
    } else {
      if (this.societyConfiguration != null) {
        getBlackboardService().publishAdd(this.societyConfiguration);
      }
    }
  }


  /**
   * No implmentation for now...
   */
  public void execute() {
    if (logger.isDebugEnabled()) {
      logger.debug(PLUGIN_NAME + " executing");
    }
  }
}
